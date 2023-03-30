//Michał Mróz 324086

#include <sys/socket.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>
#include "kod_z_wykladu.h"
#include <errno.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unordered_set>

using namespace std;
// Function that sends 3 ICMP packets to target ip
void send_packets(int socket, sockaddr_in tartget_ip, int ttl, short id){
    icmp header;
    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = htons(id);

    for (short send_pack_number = 0; send_pack_number < 3; send_pack_number++)
    {
        header.icmp_hun.ih_idseq.icd_seq = htons((send_pack_number+1)*ttl);
        header.icmp_cksum = 0;
        header.icmp_cksum = compute_icmp_checksum((u_int16_t*)&header, sizeof(header));

        setsockopt(socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
    
        sendto(socket, &header, sizeof(header), MSG_DONTWAIT, (sockaddr*)&tartget_ip, sizeof(tartget_ip));
    }
}

icmphdr* recive_packets(int socket, uint8_t *buffor, sockaddr_in *sender_addr, uint8_t *type)
{
    socklen_t sender_len = sizeof(sender_addr);

    ssize_t pack_len =  recvfrom(socket, buffor, IP_MAXPACKET, 0, (sockaddr*)sender_addr, &sender_len);

    if(pack_len < 0)
    {
        cerr << "recvfrom() error: " << strerror(errno);
        return NULL;
    }

    ip* ip_header = (ip*)buffor;
    icmphdr* icmp_header = (icmphdr*)((uint8_t*)ip_header + 4*ip_header->ip_hl);

    *type = icmp_header->type;

    if (icmp_header->type == ICMP_ECHOREPLY) // Returm ICMP if type echoreply
    {
        return icmp_header;
    } 
    else //Return icmp if other type
    {
        ip* original_ip_header = (ip*)((uint8_t*)icmp_header + sizeof(icmphdr));
        icmphdr* res = (icmphdr*)((uint8_t*)original_ip_header + 4*original_ip_header->ip_hl);

        return res;
    }
}

bool is_pack_ready(int socket, timeval* time)
{
    timeval befor, after, res;
    
    fd_set descriptor;
    FD_ZERO (&descriptor);
    FD_SET (socket, &descriptor);
    
    int respond = select(socket+1, &descriptor, NULL, NULL, time);
    
    if (respond == -1)
    {
        cerr << "select() error: " << strerror(errno);
        exit(EXIT_FAILURE);
    }
    
    return respond == 1;
}

bool no_response(unordered_set<uint32_t> &routes)
{
    return routes.empty();
}

void clear_routes(unordered_set<uint32_t> &routes)
{ 
    routes.clear();
}

void print_output(long long int *values, unordered_set<uint32_t> &routes, sockaddr_in tar_addr, int BATCH_SIZE, int ttl, uint8_t packet_type)
{
    double sum = 0;
    int avg = 0;

    for (int i = 0; i < BATCH_SIZE; i++)
    {
        if (values[i] != -1)
        {
            sum += values[i];
            values[i] = -1;
            avg++;
        }
    }

    if(no_response(routes))
    {
        cout << ttl << ". " << "* " << endl;
    }
    else if(avg == BATCH_SIZE)
    {
        cout << ttl << ". ";

        for (auto &i : routes)
        {
            cout << inet_ntoa((in_addr){i}) << " " << sum/(avg*1000) << " ms " << endl;
        }
    }
    else if(avg < BATCH_SIZE)
    {
        cout << ttl << ". ";

        for (auto &i : routes)
        {
            cout << inet_ntoa((in_addr){i}) << " ???" << endl; 
        }
    }

    if (packet_type == ICMP_ECHOREPLY)
    {
        exit(EXIT_SUCCESS);
    }
}

int main(int argc, char const *argv[])
{
    if (argc <= 1) 
    {
         cout << "No arguments." << endl;
         exit(EXIT_FAILURE);
    }
    
    // Global variables
    const char* ip = argv[1];
    int BATCH_SIZE = 3;

    timeval start_time, recive_time, onesec;
    long long int count;
    long long int values [3] = {-1};

    bool ready_to_send = true;
    bool ready_to_print = false;

    int current_ttl = 1;
    int max_ttl = 30;
     
    sockaddr_in tar_addr, sender_addr;
    unordered_set<uint32_t> routers = {};
    
    uint8_t packet_buffor[IP_MAXPACKET];
    uint8_t packet_type;
    
    if(inet_pton(AF_INET, ip, &tar_addr.sin_addr) == 0) 
    {
        cout << "ERROR: ADRESS IS INCORECT" << endl;
        exit(EXIT_FAILURE);
    }

    tar_addr.sin_family = AF_INET;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock < 0)
    {
        cout << "Opening socket failed" << endl;
        exit(EXIT_FAILURE);
    }

    short process_id = getpid();
    
    while (true)
    {
        if(ready_to_send)
        {
            if(ready_to_print)
            {
                print_output(values, routers, tar_addr, BATCH_SIZE, current_ttl, packet_type);
                clear_routes(routers);
                current_ttl++;
                if (current_ttl > max_ttl)
                {
                    break;
                }
                
            }
            
            send_packets(sock, tar_addr, current_ttl, process_id);
            ready_to_send = false;
            
            start_time = {1, 0};
            count = 0;
        }
        if (is_pack_ready(sock, &start_time))
        {
            icmphdr* packet = recive_packets(sock, packet_buffor, &sender_addr, &packet_type);

            bool valid_id = ntohs(packet->un.echo.id) == process_id;
            bool valid_seq = ntohs(packet->un.echo.sequence) >= 1*current_ttl && ntohs(packet->un.echo.sequence) <= 3*current_ttl;


            if(valid_id && valid_seq)
            {
                onesec = {1, 0};
                timersub(&onesec, &start_time, &recive_time);
                values[count] = recive_time.tv_usec;
                routers.insert(sender_addr.sin_addr.s_addr);
                count++;

                if(count == 3){
                    ready_to_send = true;
                    ready_to_print = true;
                }   
            }

            
        }
        else
        {
            ready_to_send = true;
            ready_to_print = true;            
        }

    }
    
    return 0;
}