

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

void handle_client(int client_socket); // 関数の宣言

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // ソケットの作成
    //server_fdは、待機中の接続要求を受け付けるためのソケットディスクリプタ
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        close(server_fd);
        //プログラムを終了しEXIT_FAILUREを返す．これによりプログラムの実行が強制的に中断
        exit(EXIT_FAILURE);
    }
    // アドレスの設定
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // ソケットにアドレスをバインド
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    // 接続を待つ
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    while (true) {
        std::cout << "Waiting for connections..." << std::endl;

        // 接続を受け入れる
        //accept関数は、待機中の接続要求を受け入れて、その接続のための新しいソケットを作成します
        //addressは、接続元のアドレス情報
        //addrlenは、アドレス構造体のサイズを指定
        //各クライアント接続は独自のソケットnew_socketを持つ
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        std::cout << "Connection accepted: " << inet_ntoa(address.sin_addr) << std::endl;

        // handle_client関数を新しいスレッドで実行しその引数としてnew_socketを渡す
        std::thread client_thread(handle_client, new_socket);
        //新しいスレッドをデタッチ
        client_thread.detach();
        // // メッセージの返信
        // const char *message = "Message received";
        // send(new_socket, message, strlen(message), 0);
    }
    close(new_socket);
    close(server_fd);
    return 0;
}
void handle_client(int new_socket) {
    char buffer[4096] = {0};
    // VPNトンネルを確立し、クライアントのトラフィックを処理
    // 詳細なインターネットトラフィックの送受信処理をここに追加
    // クライアントのリクエストを処理
    while (true) {
        std::cout << "Waiting for client request..." << std::endl;
        //bufferをゼロで初期化
        memset(buffer, 0, 4096);
        // インターネットに転送するソケットを設定
        int internet_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (internet_socket == -1) {
            perror("socket failed");
            continue;
            //これを失敗した場合はコンテニューでいい
        }
        //ソケットを通じてクライアントから送られてくるデータを受信
        //bufferには読み取ったデータが直接格納され、bytes_read にはそのデータの長さが格納される
        int bytes_read = read(new_socket, buffer, 4096);
        // データが読み込まれた場合
        if (bytes_read > 0) {
            std::cout << "Client request received." << std::endl;
            // データの受信と転送
            //read(new_socket, buffer, 1024);
            //std::cout << "Received data: " << buffer << std::endl;

            //sockaddr_in構造体は、IPv4アドレスとポート番号を格納するための構造体
            struct sockaddr_in internet_address;
            //構造体 internet_address をゼロで初期化
            memset(&internet_address, 0, sizeof(internet_address));
            //sin_familyフィールド
            internet_address.sin_family = AF_INET;
            //sin_portフィールド
            //htons関数はホストバイトオーダーをネットワークバイトオーダーに変換
            //ポート番号がネットワークで正しく解釈
            internet_address.sin_port = htons(80); // HTTPポート
            //リクエストにはIPアドレスでなくホスト名が含まれている
            //正規表現パターンを定義
            // リクエストからホスト名を抽出
            std::string request(buffer);
            std::vector<std::regex> host_regex_patterns = {
                std::regex("Host: (.*?)\\r\\n"),                    // HTTP/HTTPS
                std::regex("MAIL FROM:<(.*?)>"),                    // SMTP
                std::regex("IMAP.*Server: (.*?)\\r\\n"),            // IMAP
                std::regex("rtmp://(.*?)/")                         // RTMP
            };
            std::string host_name;
            //パターン全部を試したら終了する
            for (const auto& host_regex : host_regex_patterns) {
                std::smatch match;
                if (std::regex_search(request, match, host_regex) && match.size() > 1) {
                    //一致が見つかった場合（match.size() > 1）、host_nameに抽出したホスト名（match.str(1)）を格納
                    host_name = match.str(1);
                    break;
                }
            }
            if (host_name.empty()) {
                host_name = "www.example.com";
            }
            std::cout << host_name << std::endl;
            // ホスト名の解決
            struct hostent *server = gethostbyname(host_name.c_str());
            if (server == NULL) {
                perror("no such host");
                continue;
            }
            std::cout << inet_ntoa(*(struct in_addr *)server->h_addr) << std::endl;
            //DNS解決により取得されたサーバーのIPアドレス情報をinternet_address構造体のsin_addr.s_addrフィールドにコピー
            //server->h_addrは、DNS解決（gethostbyname関数）により取得されたIPアドレスの先頭アドレス
            //server->h_lengthは、IPアドレスの長さ
            memcpy(&internet_address.sin_addr.s_addr, server->h_addr, server->h_length);
            //connect関数によりinternet_socketは指定されたinternet_addressのサーバーに接続
            if (connect(internet_socket, (struct sockaddr *)&internet_address, sizeof(internet_address)) < 0) {
                perror("connect failed");
                continue;
            } else {
                std::cout << "Connected to server successfully." << std::endl;
            }
            // クライアントから受け取ったデータをインターネットに送信
            //internet_socketに対してデータを送信
            send(internet_socket, buffer, strlen(buffer), 0);
            //応答データはネットワークスタックに溜まる
            // インターネットからの応答をクライアントに転送
            while (true) {
                std::cout << "Received from internet..." << std::endl;
                //バッファを初期化
                memset(buffer, 0, sizeof(buffer));
                //internet_socketからbufferにデータを読み込む
                int bytes_received = read(internet_socket, buffer, sizeof(buffer));
                // エラーまたは接続が閉じられた合図
                if (bytes_received <= 0) {
                    break; 
                }
                std::cout << "Data received (" << bytes_received << " bytes): " 
                << std::string(buffer, std::min(bytes_received, 100)) << "..." << std::endl;
                //そうでない場合、読み取ったデータをクライアントに送信
                //new_socketが指す接続先にデータが送信
                send(new_socket, buffer, bytes_received, 0);
            }
        }
        if (bytes_read == 0) {
            // クライアントが接続を終了した合図
            std::cout << "Client disconnected" << std::endl;
            break;
            //接続終了したのでブレイクでいい
        }
        close(internet_socket);
    }
    close(new_socket);
}

// static int get_tunnel(char *port, char *secret)
// {
//     // We use an IPv6 socket to cover both IPv4 and IPv6.
//     // TCPソケットの作成
//     int tunnel = socket(AF_INET, SOCK_STREAM, 0);
//     if (tunnel < 0) {
//         perror("socket creation failed");
//         exit(EXIT_FAILURE);
//     }
//     // オプションの設定
//     int flag = 1;
//     setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    
//     // Accept packets received on any local address.
//     // ソケットアドレス構造体設定
//     // アドレスとポートの設定
//     struct sockaddr_in addr;
//     memset(&addr, 0, sizeof(addr));
//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(atoi(port));
//     addr.sin_addr.s_addr = htonl(INADDR_ANY);
//     //引数としてポートが渡されることになる

//     // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
//     // ソケットバインド
//     while (bind(tunnel, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
//         if (errno != EADDRINUSE) {
//             perror("bind failed");
//             close(tunnel);
//             exit(EXIT_FAILURE);
//         }
//         usleep(100000);
//     }
//     // リッスン設定
//     if (listen(tunnel, 5) < 0) {
//         perror("Listen failed");
//         close(tunnel);
//         exit(EXIT_FAILURE);
//     }

//     printf("Server is listening on port\n");

//     // クライアント接続受け入れ
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
