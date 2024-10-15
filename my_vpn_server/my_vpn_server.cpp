

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <netdb.h>
#include <thread>
#include <vector>
#include <regex>

#ifdef __linux__
#define PORT 8000

// There are several ways to play with this program. Here we just give an
// example for the simplest scenario. Let us say that a Linux box has a
// public IPv4 address on eth0. Please try the following steps and adjust
// the parameters when necessary.
//
// # Enable IP forwarding
// echo 1 > /proc/sys/net/ipv4/ip_forward
//
// # Pick a range of private addresses and perform NAT over eth0.
// iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
//
// # Create a TUN interface.
// ip tuntap add dev tun0 mode tun
//
// # Set the addresses and bring up the interface.
// ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
//
// # Create a server on port 8000 with shared secret "test".
// ./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
//
// This program only handles a session at a time. To allow multiple sessions,
// multiple servers can be created on the same port, but each of them requires
// its own TUN interface. A short shell script will be sufficient. Since this
// program is designed for demonstration purpose, it performs neither strong
// authentication nor encryption. DO NOT USE IT IN PRODUCTION!

#include <net/if.h>
#include <linux/if_tun.h>

// static int get_interface(char *name)
// {
//     int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

//     ifreq ifr;
//     memset(&ifr, 0, sizeof(ifr));
//     ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
//     strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

//     if (ioctl(interface, TUNSETIFF, &ifr)) {
//         perror("Cannot get TUN interface");
//         exit(1);
//     }

//     return interface;
// }

#else

#error Sorry, you have to implement this part by yourself.

#endif

void handle_client(int client_socket); // �֐��̐錾

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // �\�P�b�g�̍쐬
    //server_fd�́A�ҋ@���̐ڑ��v�����󂯕t���邽�߂̃\�P�b�g�f�B�X�N���v�^
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        close(server_fd);
        //�v���O�������I����EXIT_FAILURE��Ԃ��D����ɂ��v���O�����̎��s�������I�ɒ��f
        exit(EXIT_FAILURE);
    }
    // �A�h���X�̐ݒ�
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // �\�P�b�g�ɃA�h���X���o�C���h
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    // �ڑ���҂�
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    while (true) {
        std::cout << "Waiting for connections..." << std::endl;

        // �ڑ����󂯓����
        //accept�֐��́A�ҋ@���̐ڑ��v�����󂯓���āA���̐ڑ��̂��߂̐V�����\�P�b�g���쐬���܂�
        //address�́A�ڑ����̃A�h���X���
        //addrlen�́A�A�h���X�\���̂̃T�C�Y���w��
        //�e�N���C�A���g�ڑ��͓Ǝ��̃\�P�b�gnew_socket������
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        std::cout << "Connection accepted: " << inet_ntoa(address.sin_addr) << std::endl;

        // handle_client�֐���V�����X���b�h�Ŏ��s�����̈����Ƃ���new_socket��n��
        std::thread client_thread(handle_client, new_socket);
        //�V�����X���b�h���f�^�b�`
        client_thread.detach();
        // // ���b�Z�[�W�̕ԐM
        // const char *message = "Message received";
        // send(new_socket, message, strlen(message), 0);
    }
    close(new_socket);
    close(server_fd);
    return 0;
}
void handle_client(int new_socket) {
    char buffer[4096] = {0};
    // VPN�g���l�����m�����A�N���C�A���g�̃g���t�B�b�N������
    // �ڍׂȃC���^�[�l�b�g�g���t�B�b�N�̑���M�����������ɒǉ�
    // �N���C�A���g�̃��N�G�X�g������
    while (true) {
        std::cout << "Waiting for client request..." << std::endl;
        //buffer���[���ŏ�����
        memset(buffer, 0, 4096);
        // �C���^�[�l�b�g�ɓ]������\�P�b�g��ݒ�
        int internet_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (internet_socket == -1) {
            perror("socket failed");
            continue;
            //��������s�����ꍇ�̓R���e�j���[�ł���
        }
        //�\�P�b�g��ʂ��ăN���C�A���g���瑗���Ă���f�[�^����M
        //buffer�ɂ͓ǂݎ�����f�[�^�����ڊi�[����Abytes_read �ɂ͂��̃f�[�^�̒������i�[�����
        int bytes_read = read(new_socket, buffer, 4096);
        // �f�[�^���ǂݍ��܂ꂽ�ꍇ
        if (bytes_read > 0) {
            std::cout << "Client request received." << std::endl;
            // �f�[�^�̎�M�Ɠ]��
            //read(new_socket, buffer, 1024);
            //std::cout << "Received data: " << buffer << std::endl;

            //sockaddr_in�\���̂́AIPv4�A�h���X�ƃ|�[�g�ԍ����i�[���邽�߂̍\����
            struct sockaddr_in internet_address;
            //�\���� internet_address ���[���ŏ�����
            memset(&internet_address, 0, sizeof(internet_address));
            //sin_family�t�B�[���h
            internet_address.sin_family = AF_INET;
            //sin_port�t�B�[���h
            //htons�֐��̓z�X�g�o�C�g�I�[�_�[���l�b�g���[�N�o�C�g�I�[�_�[�ɕϊ�
            //�|�[�g�ԍ����l�b�g���[�N�Ő���������
            internet_address.sin_port = htons(80); // HTTP�|�[�g
            //���N�G�X�g�ɂ�IP�A�h���X�łȂ��z�X�g�����܂܂�Ă���
            //���K�\���p�^�[�����`
            // ���N�G�X�g����z�X�g���𒊏o
            std::string request(buffer);
            std::vector<std::regex> host_regex_patterns = {
                std::regex("Host: (.*?)\\r\\n"),                    // HTTP/HTTPS
                std::regex("MAIL FROM:<(.*?)>"),                    // SMTP
                std::regex("IMAP.*Server: (.*?)\\r\\n"),            // IMAP
                std::regex("rtmp://(.*?)/")                         // RTMP
            };
            std::string host_name;
            //�p�^�[���S������������I������
            for (const auto& host_regex : host_regex_patterns) {
                std::smatch match;
                if (std::regex_search(request, match, host_regex) && match.size() > 1) {
                    //��v�����������ꍇ�imatch.size() > 1�j�Ahost_name�ɒ��o�����z�X�g���imatch.str(1)�j���i�[
                    host_name = match.str(1);
                    break;
                }
            }
            if (host_name.empty()) {
                host_name = "www.example.com";
            }
            std::cout << host_name << std::endl;
            // �z�X�g���̉���
            struct hostent *server = gethostbyname(host_name.c_str());
            if (server == NULL) {
                perror("no such host");
                continue;
            }
            std::cout << inet_ntoa(*(struct in_addr *)server->h_addr) << std::endl;
            //DNS�����ɂ��擾���ꂽ�T�[�o�[��IP�A�h���X����internet_address�\���̂�sin_addr.s_addr�t�B�[���h�ɃR�s�[
            //server->h_addr�́ADNS�����igethostbyname�֐��j�ɂ��擾���ꂽIP�A�h���X�̐擪�A�h���X
            //server->h_length�́AIP�A�h���X�̒���
            memcpy(&internet_address.sin_addr.s_addr, server->h_addr, server->h_length);
            //connect�֐��ɂ��internet_socket�͎w�肳�ꂽinternet_address�̃T�[�o�[�ɐڑ�
            if (connect(internet_socket, (struct sockaddr *)&internet_address, sizeof(internet_address)) < 0) {
                perror("connect failed");
                continue;
            } else {
                std::cout << "Connected to server successfully." << std::endl;
            }
            // �N���C�A���g����󂯎�����f�[�^���C���^�[�l�b�g�ɑ��M
            //internet_socket�ɑ΂��ăf�[�^�𑗐M
            send(internet_socket, buffer, strlen(buffer), 0);
            //�����f�[�^�̓l�b�g���[�N�X�^�b�N�ɗ��܂�
            // �C���^�[�l�b�g����̉������N���C�A���g�ɓ]��
            while (true) {
                std::cout << "Received from internet..." << std::endl;
                //�o�b�t�@��������
                memset(buffer, 0, sizeof(buffer));
                //internet_socket����buffer�Ƀf�[�^��ǂݍ���
                int bytes_received = read(internet_socket, buffer, sizeof(buffer));
                // �G���[�܂��͐ڑ�������ꂽ���}
                if (bytes_received <= 0) {
                    break; 
                }
                std::cout << "Data received (" << bytes_received << " bytes): " 
                << std::string(buffer, std::min(bytes_received, 100)) << "..." << std::endl;
                //�����łȂ��ꍇ�A�ǂݎ�����f�[�^���N���C�A���g�ɑ��M
                //new_socket���w���ڑ���Ƀf�[�^�����M
                send(new_socket, buffer, bytes_received, 0);
            }
        }
        if (bytes_read == 0) {
            // �N���C�A���g���ڑ����I���������}
            std::cout << "Client disconnected" << std::endl;
            break;
            //�ڑ��I�������̂Ńu���C�N�ł���
        }
        close(internet_socket);
    }
    close(new_socket);
}

// static int get_tunnel(char *port, char *secret)
// {
//     // We use an IPv6 socket to cover both IPv4 and IPv6.
//     // TCP�\�P�b�g�̍쐬
//     int tunnel = socket(AF_INET, SOCK_STREAM, 0);
//     if (tunnel < 0) {
//         perror("socket creation failed");
//         exit(EXIT_FAILURE);
//     }
//     // �I�v�V�����̐ݒ�
//     int flag = 1;
//     setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    
//     // Accept packets received on any local address.
//     // �\�P�b�g�A�h���X�\���̐ݒ�
//     // �A�h���X�ƃ|�[�g�̐ݒ�
//     struct sockaddr_in addr;
//     memset(&addr, 0, sizeof(addr));
//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(atoi(port));
//     addr.sin_addr.s_addr = htonl(INADDR_ANY);
//     //�����Ƃ��ă|�[�g���n����邱�ƂɂȂ�

//     // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
//     // �\�P�b�g�o�C���h
//     while (bind(tunnel, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
//         if (errno != EADDRINUSE) {
//             perror("bind failed");
//             close(tunnel);
//             exit(EXIT_FAILURE);
//         }
//         usleep(100000);
//     }
//     // ���b�X���ݒ�
//     if (listen(tunnel, 5) < 0) {
//         perror("Listen failed");
//         close(tunnel);
//         exit(EXIT_FAILURE);
//     }

//     printf("Server is listening on port\n");

//     // �N���C�A���g�ڑ��󂯓���
//     int clientSocket = accept(tunnel, NULL, NULL);
//     if (clientSocket < 0) {
//         perror("Accept failed");
//         close(tunnel);
//         exit(EXIT_FAILURE);
//     }
//     printf("Client connected\n");

//     // Receive packets till the secret matches.
//     char packet[1024];
//     socklen_t addrlen;
//     do {
//         addrlen = sizeof(addr);
//         int n = recvfrom(tunnel, packet, sizeof(packet), 0,
//                 (sockaddr *)&addr, &addrlen);
//         if (n <= 0) {
//             perror("recvfrom failed");
//             return -1;
//         }
//         packet[n] = 0;
//     } while (packet[0] != 0 || strcmp(secret, &packet[1]));

//     // Connect to the client as we only handle one client at a time.
//     if (connect(tunnel, (sockaddr *)&addr, addrlen)< 0) {
//         perror("connect failed");
//         return -1;
//     }
//     return tunnel;
// }

// static void build_parameters(char *parameters, int size, int argc, char **argv)
// {
//     // Well, for simplicity, we just concatenate them (almost) blindly.
//     int offset = 0;
//     for (int i = 4; i < argc; ++i) {
//         char *parameter = argv[i];
//         int length = strlen(parameter);
//         char delimiter = ',';

//         // If it looks like an option, prepend a space instead of a comma.
//         if (length == 2 && parameter[0] == '-') {
//             ++parameter;
//             --length;
//             delimiter = ' ';
//         }

//         // This is just a demo app, really.
//         if (offset + length >= size) {
//             puts("Parameters are too large");
//             exit(1);
//         }

//         // Append the delimiter and the parameter.
//         parameters[offset] = delimiter;
//         memcpy(&parameters[offset + 1], parameter, length);
//         offset += 1 + length;
//     }

//     // Fill the rest of the space with spaces.
//     memset(&parameters[offset], ' ', size - offset);

//     // Control messages always start with zero.
//     parameters[0] = 0;
// }

// //-----------------------------------------------------------------------------

// int main(int argc, char **argv)
// {
//     if (argc < 5) {
//         printf("Usage: %s <tunN> <port> <secret> options...\n"
//                "\n"
//                "Options:\n"
//                "  -m <MTU> for the maximum transmission unit\n"
//                "  -a <address> <prefix-length> for the private address\n"
//                "  -r <address> <prefix-length> for the forwarding route\n"
//                "  -d <address> for the domain name server\n"
//                "  -s <domain> for the search domain\n"
//                "\n"
//                "Note that TUN interface needs to be configured properly\n"
//                "BEFORE running this program. For more information, please\n"
//                "read the comments in the source code.\n\n", argv[0]);
//         exit(1);
//     }

//     // Parse the arguments and set the parameters.
//     char parameters[1024];
//     build_parameters(parameters, sizeof(parameters), argc, argv);

//     // Get TUN interface.
//     int interface = get_interface(argv[1]);

//     // Wait for a tunnel.
//     int tunnel;
//     while ((tunnel = get_tunnel(argv[2], argv[3])) != -1) {
//         printf("%s: Here comes a new tunnel\n", argv[1]);

//         // On UN*X, there are many ways to deal with multiple file
//         // descriptors, such as poll(2), select(2), epoll(7) on Linux,
//         // kqueue(2) on FreeBSD, pthread(3), or even fork(2). Here we
//         // mimic everything from the client, so their source code can
//         // be easily compared side by side.

//         // Put the tunnel into non-blocking mode.
//         fcntl(tunnel, F_SETFL, O_NONBLOCK);

//         // Send the parameters several times in case of packet loss.
//         for (int i = 0; i < 3; ++i) {
//             send(tunnel, parameters, sizeof(parameters), MSG_NOSIGNAL);
//         }

//         // Allocate the buffer for a single packet.
//         char packet[32767];

//         // We use a timer to determine the status of the tunnel. It
//         // works on both sides. A positive value means sending, and
//         // any other means receiving. We start with receiving.
//         int timer = 0;

//         // We keep forwarding packets till something goes wrong.
//         while (true) {
//             // Assume that we did not make any progress in this iteration.
//             bool idle = true;

//             // Read the outgoing packet from the input stream.
//             int length = read(interface, packet, sizeof(packet));
//             if (length > 0) {
//                 // Write the outgoing packet to the tunnel.
//                 send(tunnel, packet, length, MSG_NOSIGNAL);

//                 // There might be more outgoing packets.
//                 idle = false;

//                 // If we were receiving, switch to sending.
//                 if (timer < 1) {
//                     timer = 1;
//                 }
//             }

//             // Read the incoming packet from the tunnel.
//             length = recv(tunnel, packet, sizeof(packet), 0);
//             if (length == 0) {
//                 break;
//             }
//             if (length > 0) {
//                 // Ignore control messages, which start with zero.
//                 if (packet[0] != 0) {
//                     // Write the incoming packet to the output stream.
//                     write(interface, packet, length);
//                 }

//                 // There might be more incoming packets.
//                 idle = false;

//                 // If we were sending, switch to receiving.
//                 if (timer > 0) {
//                     timer = 0;
//                 }
//             }

//             // If we are idle or waiting for the network, sleep for a
//             // fraction of time to avoid busy looping.
//             if (idle) {
//                 usleep(100000);

//                 // Increase the timer. This is inaccurate but good enough,
//                 // since everything is operated in non-blocking mode.
//                 timer += (timer > 0) ? 100 : -100;

//                 // We are receiving for a long time but not sending.
//                 // Can you figure out why we use a different value? :)
//                 if (timer < -16000) {
//                     // Send empty control messages.
//                     packet[0] = 0;
//                     for (int i = 0; i < 3; ++i) {
//                         send(tunnel, packet, 1, MSG_NOSIGNAL);
//                     }

//                     // Switch to sending.
//                     timer = 1;
//                 }

//                 // We are sending for a long time but not receiving.
//                 if (timer > 20000) {
//                     break;
//                 }
//             }
//         }
//         printf("%s: The tunnel is broken\n", argv[1]);
//         close(tunnel);
//     }
//     perror("Cannot create tunnels");
//     exit(1);
// }
