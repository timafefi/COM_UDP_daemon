#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <poll.h>
#include <string.h>
#define UDP (17)
#define MSG_LEN 64


int socat_pid;
char flag = 0;
struct pollfd sockpfd, compfd;
struct sockaddr udp_addr;
socklen_t udp_addr_len = sizeof(udp_addr);


void sigint_handler(int signum)
{
    flag = 1;
}

void report_error_and_exit(char *errmsg)
{
    kill(socat_pid, SIGINT);
    wait(NULL);
    close(compfd.fd);
    close(sockpfd.fd);
    perror(errmsg);
    exit(1);
}

struct pollfd get_pfds(int fd, short events, short revents)
{
    struct pollfd p;
    p.fd = fd;
    p.events = events;
    p.revents = revents;
    return p;
}


void create_tty_virt()
{
    int pid;
    if (0 == (pid = fork())){
        char ttyS0[] = "pty,raw,echo=0,link=./ttyS0";
        char ttyS1[] = "pty,raw,echo=0,link=./ttyS1";
        execl("/bin/socat", "socat", "-d", "-d", ttyS0, ttyS1, NULL);
        perror("socat");
        exit(1);
    }
    socat_pid = pid;
}


int open_ttyS0()
{
    int fd, i;
    for(i = 0; i < 3; i++){
        if (-1 == (fd = (open("./ttyS0", O_RDWR|O_NONBLOCK)))){
            if(i>2){
                report_error_and_exit("open");
            }
            sleep(1);
        }
    }
    return fd;
}


struct pollfd setup_comport()
{
    create_tty_virt();
    return get_pfds(open_ttyS0(), POLLIN, 0);
}


struct pollfd create_socket(int port)
{
    int sock_fd;
    struct sockaddr_in addr = {0};
    int opt = 1;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(-1 == (sock_fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, UDP)))
        report_error_and_exit("socket");
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (0 != bind(sock_fd, (struct sockaddr *) &addr, sizeof(addr)))
        report_error_and_exit("bind");
    return get_pfds(sock_fd, POLLIN, 0);
}


int get_port(int argc, char **argv){
    if (argc < 2){
        fprintf(stderr, "Error: Please, specify port\n");
        exit(1);
    }
    return atoi(argv[1]);
}


void sock_to_com(int from, int to)
{
    char msg[MSG_LEN];
    int rc;
    memset(msg, 0, MSG_LEN);
    if(-1 == (rc = recvfrom(from, msg, MSG_LEN, 0, &udp_addr, &udp_addr_len)))
        report_error_and_exit("recvfrom");
    if(-1 == (write(to, msg, rc)))
        report_error_and_exit("write");
}

void com_to_sock(int from, int to)
{
    char msg[MSG_LEN];
    int rc;
    memset(msg, 0, MSG_LEN);
    if(-1 == (rc = read(from, msg, MSG_LEN)))
        report_error_and_exit("read");
    if(-1 == (sendto(to, msg, rc, 0, &udp_addr, udp_addr_len))){
        //udp_addr is empty. Serial port has to write first
        perror("Error, perhaps socket is not connected yet");
    }
}

void socketloop(struct pollfd sockpfd, struct pollfd compfd)
{
    int res;
    struct pollfd pfds[2];
    pfds[0] = sockpfd;
    pfds[1] = compfd;

    while(!flag){
        res = poll(pfds, sizeof(pfds)/sizeof(pfds[0]), 10000);
        if(res == -1)
            report_error_and_exit("poll");
        if(pfds[0].revents)
            sock_to_com(pfds[0].fd, pfds[1].fd);
        if(pfds[1].revents)
            com_to_sock(pfds[1].fd, pfds[0].fd);
    }

}


struct termios raw_tty(int fd)
{
    struct termios old, new;
    tcgetattr(fd, &old);
    new = old;
    //new.c_cc[VMIN] = 0;
    //new.c_cc[VTIME] = 1;
    if(-1 == tcsetattr(fd, TCSANOW, &new))
        report_error_and_exit("tcsetattr");
    //ERROR: Inappropriate ioctl for device

    return old;
}


int main(int argc, char **argv){
    int port;
    struct termios sock_orig;
    signal(SIGINT, sigint_handler);
    port = get_port(argc, argv);
    compfd = setup_comport();
    sockpfd = create_socket(port);
    //sock_orig = raw_tty(sockpfd.fd);
    socketloop(sockpfd, compfd);
    if(-1 == tcsetattr(sockpfd.fd, TCSANOW, &sock_orig))
        report_error_and_exit("tcsetattr");
    close(compfd.fd);
    close(sockpfd.fd);
    kill(socat_pid, SIGINT);
    wait(NULL);
    return 0;
}

