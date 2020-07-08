/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>

#include "util.h"
#include "messagebus.h"
#include "ipc_remote2.h"
#include "pollabletracker.h"

ipc_remote_v2::ipc_remote_v2(global_registry *in_globalreg, 
        std::shared_ptr<buffer_handler_generic> in_rbhandler) :
        globalreg {Globalreg::globalreg},
        tracker_free {false},
        child_pid {0} {

    pollabletracker =
        Globalreg::fetch_mandatory_global_as<pollable_tracker>();

    remotehandler = 
        Globalreg::fetch_mandatory_global_as<ipc_remote_v2_tracker>();

    tracker_free = false;

    // Inherit the mutex from the rbhandler
    ipc_mutex = in_rbhandler->get_mutex();

    ipchandler = in_rbhandler;

    ipchandler->set_protocol_error_cb([this]() {
        close_ipc();
    });

}

void ipc_remote_v2::set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    if (in_parent == nullptr)
        in_parent = std::make_shared<kis_recursive_timed_mutex>();

    local_locker l(ipc_mutex);

    ipc_mutex = in_parent;

    pipeclient->set_mutex(ipc_mutex);
}

ipc_remote_v2::~ipc_remote_v2() {
    if (pipeclient != nullptr) {
        pollabletracker->remove_pollable(pipeclient);
        pipeclient->close_pipes();
    }

    if (ipchandler != nullptr) {
        ipchandler->set_protocol_error_cb([]() { });
        ipchandler->buffer_error("IPC process has closed");
    }

    hard_kill();
}

void ipc_remote_v2::add_path(std::string in_path) {
    local_locker lock(ipc_mutex);
    path_vec.push_back(in_path);
}

std::string ipc_remote_v2::FindBinaryPath(std::string in_cmd) {
    local_locker lock(ipc_mutex);

    for (unsigned int x = 0; x < path_vec.size(); x++) {
        std::stringstream path;
        struct stat buf;

        path << path_vec[x] << "/" << in_cmd;

        auto str = path.str();

        if (stat(str.c_str(), &buf) < 0)
            continue;

        if (buf.st_mode & S_IXUSR)
            return path.str();
    }

    return "";
}

void ipc_remote_v2::close_ipc() {
    local_locker lock(ipc_mutex);

    if (pipeclient != nullptr) {
        pollabletracker->remove_pollable(pipeclient);
        pipeclient->close_pipes();
    }

    if (ipchandler != nullptr) {
        ipchandler->set_protocol_error_cb([]() { });
        ipchandler->buffer_error("IPC process has closed");
    }

    pipeclient.reset();
    ipchandler.reset();

    hard_kill();
}

int ipc_remote_v2::launch_kis_binary(std::string cmd, std::vector<std::string> args) {
    std::string fullcmd = FindBinaryPath(cmd);

    if (fullcmd == "") {
        _MSG_ERROR("IPC could not find binary '{}'", cmd);
        return -1;
    }

    return launch_kis_explicit_binary(fullcmd, args);
}

int ipc_remote_v2::launch_kis_explicit_binary(std::string cmdpath, std::vector<std::string> args) {
    struct stat buf;
    char **cmdarg;
    std::stringstream arg;

    if (stat(cmdpath.c_str(), &buf) < 0) {
        _MSG_ERROR("IPC could not find binary '{}", cmdpath);
        return -1;
    }

    if (!(buf.st_mode & S_IXOTH)) {
        if (getuid() != buf.st_uid && getuid() != 0) {
            bool group_ok = false;
            gid_t *groups;
            int ngroups;

            if (getgid() != buf.st_gid) {
                ngroups = getgroups(0, NULL);

                if (ngroups > 0) {
                    groups = new gid_t[ngroups];
                    ngroups = getgroups(ngroups, groups);

                    for (int g = 0; g < ngroups; g++) {
                        if (groups[g] == buf.st_gid) {
                            group_ok = true;
                            break;
                        }
                    }

                    delete[] groups;
                }

                if (!group_ok) {
                    _MSG_ERROR("IPC cannot run binary '{}', Kismet was installed "
                            "setgid and you are not in that group. If you recently added your "
                            "user to the kismet group, you will need to log out and back in to "
                            "activate it.  You can check your groups with the 'groups' command.",
                            cmdpath);
                    return -1;
                }
            }
        }
    }

    // We can't use a local_locker here because we can't let it unlock
    // inside the child thread, because the mutex doesn't survive across
    // forking
    local_eol_locker ilock(ipc_mutex);

    // 'in' to the spawned process, write to the server process, 
    // [1] belongs to us, [0] to them
    int inpipepair[2];
    // 'out' from the spawned process, read to the server process, 
    // [0] belongs to us, [1] to them
    int outpipepair[2];

#ifdef HAVE_PIPE2
    if (pipe2(inpipepair, O_NONBLOCK) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        local_unlocker ulock(ipc_mutex);
        return -1;
    }

    if (pipe2(outpipepair, O_NONBLOCK) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        close(inpipepair[0]);
        close(inpipepair[1]);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }
#else
    if (pipe(inpipepair) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        local_unlocker ulock(ipc_mutex);
        return -1;
    }
    fcntl(inpipepair[0], F_SETFL, fcntl(inpipepair[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(inpipepair[1], F_SETFL, fcntl(inpipepair[1], F_GETFL, 0) | O_NONBLOCK);

    if (pipe(outpipepair) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        close(inpipepair[0]);
        close(inpipepair[1]);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }
    fcntl(outpipepair[0], F_SETFL, fcntl(outpipepair[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(outpipepair[1], F_SETFL, fcntl(outpipepair[1], F_GETFL, 0) | O_NONBLOCK);

#endif

    // We don't need to do signal masking because we run a dedicated signal handling thread

    if ((child_pid = fork()) < 0) {
        _MSG_ERROR("IPC could not fork(): {}", kis_strerror_r(errno));
        local_unlocker ulock(ipc_mutex);
    } else if (child_pid == 0) {
        // We're the child process

        // Unblock all signals in the child so nothing carries over from the parent fork
        sigset_t unblock_mask;
        sigfillset(&unblock_mask);
        pthread_sigmask(SIG_UNBLOCK, &unblock_mask, nullptr);
      
        // argv[0], "--in-fd" "--out-fd" ... NULL
        cmdarg = new char*[args.size() + 4];
        cmdarg[0] = strdup(cmdpath.c_str());

        // Child reads from inpair
        arg << "--in-fd=" << inpipepair[0];
        auto argstr = arg.str();
        cmdarg[1] = strdup(argstr.c_str());
        arg.str("");

        // Child writes to writepair
        arg << "--out-fd=" << outpipepair[1];
        argstr = arg.str();
        cmdarg[2] = strdup(argstr.c_str());

        for (unsigned int x = 0; x < args.size(); x++)
            cmdarg[x+3] = strdup(args[x].c_str());

        cmdarg[args.size() + 3] = NULL;

        // close the unused half of the pairs on the child
        close(inpipepair[1]);
        close(outpipepair[0]);

        // fprintf(stderr, "debug - ipcremote2 - exec %s\n", cmdarg[0]);
        execvp(cmdarg[0], cmdarg);

        exit(255);
    } 

    // fprintf(stderr, "forked, child pid %d\n", child_pid);
   
    // Parent process
   
    // fprintf(stderr, "debug - ipcremote2 creating pipeclient\n");
    
    
    // close the remote side of the pipes from the parent, they're open in the child
    close(inpipepair[0]);
    close(outpipepair[1]);

    if (pipeclient != NULL) {
        soft_kill();
    }

    pipeclient.reset(new pipe_client(globalreg, ipchandler));

    // Read from the child write pair, write to the child read pair
    pipeclient->open_pipes(outpipepair[0], inpipepair[1]);

    pollabletracker->register_pollable(pipeclient);

    binary_path = cmdpath;
    binary_args = args;

    {
        local_unlocker ulock(ipc_mutex);
    }

    return 1;
}

int ipc_remote_v2::launch_standard_binary(std::string cmd, std::vector<std::string> args) {
    std::string fullcmd = FindBinaryPath(cmd);

    if (fullcmd == "") {
        _MSG_ERROR("IPC could not find binary '{}'", cmd);
        return -1;
    }

    return launch_standard_explicit_binary(fullcmd, args);
}

int ipc_remote_v2::launch_standard_explicit_binary(std::string cmdpath, std::vector<std::string> args) {
    struct stat buf;
    char **cmdarg;
    std::stringstream arg;

    if (pipeclient != NULL) {
        soft_kill();
    }

    if (stat(cmdpath.c_str(), &buf) < 0) {
        _MSG_ERROR("IPC could not find binary '{}'", cmdpath);
        return -1;
    }

    if (!(buf.st_mode & S_IXUSR)) {
        _MSG_ERROR("IPC could not find binary '{}'", cmdpath);
        return -1;
    }

    // We can't use a local_locker here because we can't let it unlock
    // inside the child thread, because the mutex doesn't survive across
    // forking
    local_eol_locker elock(ipc_mutex);

    // 'in' to the spawned process, [0] belongs to us, [1] to them
    int inpipepair[2];
    // 'out' from the spawned process, [1] belongs to us, [0] to them
    int outpipepair[2];

    if (pipe(inpipepair) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        local_unlocker ulock(ipc_mutex);
        return -1;
    }

    if (pipe(outpipepair) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        close(inpipepair[0]);
        close(inpipepair[1]);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }

    // We don't do signal masking because we run a dedicated signal handling thread

    if ((child_pid = fork()) < 0) {
        _MSG_ERROR("IPC could not fork(): {}", kis_strerror_r(errno));
        local_unlocker ulock(ipc_mutex);
    } else if (child_pid == 0) {
        // We're the child process
        
        // Unblock all signals in the child so nothing carries over from the parent fork
        sigset_t unblock_mask;
        sigfillset(&unblock_mask);
        pthread_sigmask(SIG_UNBLOCK, &unblock_mask, nullptr);

        // argv[0], "--in-fd" "--out-fd" ... NULL
        cmdarg = new char*[args.size() + 1];
        cmdarg[0] = strdup(cmdpath.c_str());

        for (unsigned int x = 0; x < args.size(); x++)
            cmdarg[x+3] = strdup(args[x].c_str());

        cmdarg[args.size() + 1] = NULL;

        // Clone over the stdin/stdout
        dup2(inpipepair[0], STDIN_FILENO);
        dup2(outpipepair[1], STDOUT_FILENO);

        // close the remote side of the pipes
        close(inpipepair[0]);
        close(outpipepair[1]);

        execvp(cmdarg[0], cmdarg);

        exit(255);
    } 

    // Only reach here if we're the parent process
    
    // close the remote side of the pipes
    close(inpipepair[1]);
    close(outpipepair[0]);

    pipeclient.reset(new pipe_client(globalreg, ipchandler));

    pollabletracker->register_pollable(pipeclient);

    // We read from the read end of the out pair, and write to the write end of the in
    // pair.  Confused?
    pipeclient->open_pipes(outpipepair[0], inpipepair[1]);

    binary_path = cmdpath;
    binary_args = args;

    {
        local_unlocker ulock(ipc_mutex);
    }

    return 1;
}

pid_t ipc_remote_v2::get_pid() {
    return child_pid;
}

void ipc_remote_v2::set_tracker_free(bool in_free) {
    local_locker lock(ipc_mutex);
    tracker_free = in_free;
}

int ipc_remote_v2::soft_kill() {
    local_locker lock(ipc_mutex);

    if (pipeclient != nullptr) {
        pollabletracker->remove_pollable(pipeclient);
        pipeclient->close_pipes();
    }

    if (child_pid <= 0)
        return -1;

    return kill(child_pid, SIGTERM);
}

int ipc_remote_v2::hard_kill() {
    local_locker lock(ipc_mutex);

    if (pipeclient != nullptr) {
        pollabletracker->remove_pollable(pipeclient);
        pipeclient->close_pipes();
    }

    if (child_pid <= 0) {
        return -1;
    }

    return kill(child_pid, SIGKILL);
}

void ipc_remote_v2::notify_killed(int in_exit) {
    local_locker l(ipc_mutex);

    std::stringstream ss;

    // Pull anything left in the buffer and process it
    if (pipeclient != nullptr) {
        pipeclient->flush_read();
    }

    if (ipchandler != nullptr) {
        ss << "IPC process '" << binary_path << "' " << child_pid << " exited, " << in_exit;
        ipchandler->buffer_error(ss.str());
    }

    close_ipc();
}

ipc_remote_v2_tracker::ipc_remote_v2_tracker(global_registry *in_globalreg) {
    ipc_mutex.set_name("ipc_remote_v2_tracker");

    globalreg = in_globalreg;

    timer_id = 
        globalreg->timetracker->register_timer(SERVER_TIMESLICES_SEC, NULL, 1, this);
    cleanup_timer_id = -1;
}

ipc_remote_v2_tracker::~ipc_remote_v2_tracker() {
    globalreg->RemoveGlobal("IPCHANDLER");

    globalreg->timetracker->remove_timer(timer_id);
    globalreg->timetracker->remove_timer(cleanup_timer_id);
}

void ipc_remote_v2_tracker::add_ipc(std::shared_ptr<ipc_remote_v2> in_remote) {
    local_locker lock(&ipc_mutex);

    if (in_remote == nullptr) {
        // fmt::print(stderr, "debug - tried to add null remote\n");
        return;
    }

    if (in_remote->get_pid() <= 0) {
        // fmt::print(stderr, "debug - tried to add ipc proc w/ no pid\n");
        return;
    }

    for (auto r : process_vec) {
        if (r->get_pid() == in_remote->get_pid()) {
            // fmt::print(stderr, "debug - ipc tried to add process {} but already extant\n");
            return;
        }
    }

    process_vec.push_back(in_remote);

    // fmt::print(stderr, "debug - + ipc {} process vec {}\n", in_remote->get_pid(), process_vec.size());
}

std::shared_ptr<ipc_remote_v2> ipc_remote_v2_tracker::remove_ipc(ipc_remote_v2 *in_remote) {
    local_locker lock(&ipc_mutex);

    std::shared_ptr<ipc_remote_v2> ret;

    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (process_vec[x].get() == in_remote) {
            ret = process_vec[x];
            // fmt::print(stderr, "debug - ipc removing by ptr pid {}\n", ret->get_pid());
            cleanup_vec.push_back(ret);
            process_vec.erase(process_vec.begin() + x);
            break;
        }
    }

    // fmt::print(stderr, "debug - ipc schedule cleanup process vec {}\n", process_vec.size());
    schedule_cleanup();

    return ret;
}

void ipc_remote_v2_tracker::schedule_cleanup() {
    if (cleanup_timer_id > 0)
        return;

    cleanup_timer_id = 
        Globalreg::globalreg->timetracker->register_timer(2, NULL, 0, 
                [this] (int) -> int {
                    local_locker lock(&ipc_mutex);
                    cleanup_vec.clear();
                    cleanup_timer_id = 0;
                    return 0;
                });

}

std::shared_ptr<ipc_remote_v2> ipc_remote_v2_tracker::remove_ipc(pid_t in_pid) {
    local_locker lock(&ipc_mutex);

    std::shared_ptr<ipc_remote_v2> ret;

    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (process_vec[x]->get_pid() == in_pid) {
            ret = process_vec[x];
            // fmt::print(stderr, "debug - ipc removing by pid {}\n", ret->get_pid());
            cleanup_vec.push_back(ret);
            process_vec.erase(process_vec.begin() + x);
            break;
        }
    }

    // fmt::print(stderr, "debug - ipc schedule cleanup process vec {}\n", process_vec.size());
    schedule_cleanup();

    return ret;
}

void ipc_remote_v2_tracker::kill_all_ipc(bool in_hardkill) {
    local_locker lock(&ipc_mutex);

    // Leave everything in the vec until we properly reap it, we might
    // need to go back and kill it again
    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (in_hardkill)
            process_vec[x]->hard_kill();
        else
            process_vec[x]->soft_kill();
    }
}

int ipc_remote_v2_tracker::ensure_all_ipc_killed(int in_soft_delay, int in_max_delay) {
    // We can't immediately lock since killall will need to

    // Soft-kill every process
    kill_all_ipc(false);

    time_t start_time = time(0);

    // It would be more efficient to hijack the signal handler here and
    // use our own timer, but that's a hassle and this only happens during
    // shutdown.  We do a spin on waitpid instead.

    while (1) {
        int pid_status;
        pid_t caught_pid;
        std::shared_ptr<ipc_remote_v2> killed_remote;

        caught_pid = waitpid(-1, &pid_status, WNOHANG);

        // If we caught a pid, blindly remove it from the vec, we don't
        // care if we caught a pid we don't know about I suppose
        if (caught_pid > 0) {
            killed_remote = remove_ipc(caught_pid);

            // TODO decide if we're going to delete the IPC handler too
            if (killed_remote != nullptr) {
                killed_remote->notify_killed(WEXITSTATUS(pid_status)); 
            }
        } else {
            // Sleep if we haven't caught anything, otherwise spin to catch all
            // pending processes
            usleep(100);
        }

        if (time(0) - start_time > in_soft_delay)
            break;
    }

    bool vector_empty = true;

    {
        local_locker lock(&ipc_mutex);
        if (process_vec.size() > 0)
            vector_empty = false;
    }

    // If we've run out of time, stop
    if (time(0) - start_time > in_max_delay) {
        if (vector_empty)
            return 0;
        return -1;
    }

    // If we need to kill things the hard way
    if (!vector_empty) {
        kill_all_ipc(true);

        while (1) {
            int pid_status;
            pid_t caught_pid;
            std::shared_ptr<ipc_remote_v2> killed_remote;

            caught_pid = waitpid(-1, &pid_status, WNOHANG);

            // If we caught a pid, blindly remove it from the vec, we don't
            // care if we caught a pid we don't know about I suppose
            if (caught_pid > 0) {
                killed_remote = remove_ipc(caught_pid);

                // TODO decide if we're going to delete the IPC handler too
                if (killed_remote != NULL)
                    killed_remote->notify_killed(WEXITSTATUS(pid_status));
            } else {
                // Sleep if we haven't caught anything, otherwise spin to catch all
                // pending processes
                usleep(1000);
            }

            if (in_max_delay != 0 && time(0) - start_time > in_max_delay)
                break;
        }
    }

    {
        local_locker lock(&ipc_mutex);
        if (process_vec.size() > 0)
            vector_empty = false;
    }

    if (vector_empty)
        return 0;

    return -1;
}

int ipc_remote_v2_tracker::timetracker_event(int event_id __attribute__((unused))) {
    std::stringstream str;
    std::shared_ptr<ipc_remote_v2> dead_remote;

    int pid_status;
    pid_t caught_pid;

    if (globalreg->reap_child_procs) {
        globalreg->reap_child_procs = false;

        while ((caught_pid = waitpid(-1, &pid_status, WNOHANG | WUNTRACED)) > 0) {
            // Find the IPC record for this remote
            dead_remote = remove_ipc(caught_pid);

            // Kill it
            if (dead_remote != nullptr) {
                dead_remote->notify_killed(0);
                dead_remote->close_ipc();
            }
        }
    }

    // fmt::print(stderr, "debug - process vec size {}\n", process_vec.size());
    for (auto p : process_vec) {
        if (p == nullptr)
            continue;

        // fmt::print(stderr, "PROC {}\n", p->get_pid());
        
        caught_pid = waitpid(p->get_pid(), &pid_status, WNOHANG | WUNTRACED);

        if (caught_pid < 0) {
            // fmt::print(stderr, "debug - looks like we missed pid {} somehow, removing\n", p->get_pid());

            // Find the IPC record for this remote
            dead_remote = remove_ipc(p->get_pid());

            // Kill it
            if (dead_remote != nullptr) {
                dead_remote->notify_killed(0);
                dead_remote->close_ipc();
            }
        }
    }

    return 1;
}

