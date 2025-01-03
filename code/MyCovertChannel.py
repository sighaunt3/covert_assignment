from CovertChannelBase import CovertChannelBase
import random, time
from scapy.all import IP, TCP, sniff,send

class MyCovertChannel(CovertChannelBase):
    
    """
    Covert Timing Channel that exploits Idle Period Between Packet Bursts using TCP [Code: CTC-IPPB-TCP]
    """
    def __init__(self):
        super().__init__()
        self.random = random
        self.is_dot = False
        self.i = 1 
        
    def send(self, log_file_name, src_ip, dst_ip, dst_port, min_packets, max_packets, delay_1_min, delay_1_max, delay_0_min, delay_0_max,zero,one):
        """
        This function creates a random binary message and sends it to the receiver container.
        It generates a random binary message using a function from CovertChannelBase.
        For each bit in the message, it generates a random number of packets and stores them in a list called num_packets. Once every all the packets have been created for that
        bit the list is sent to the receiver all together in one burst.
        The delay between bursts of packets is adjusted based on whether the bit is '0' or '1'.
        The function logs the binary message.
    """
        
        binary_message = self.generate_random_binary_message_with_logging("sender.log")
     
        start_time = time.time()

        for bit in binary_message:
            num_packets = self.random.randint(min_packets, max_packets)
            burst_packets = [] 
            for i in range(num_packets):
                x = time.time()
                packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
                burst_packets.append(packet)
            send(burst_packets,verbose =False)
            if bit == one:
                self.sleep_random_time_ms(delay_1_min, delay_1_max)
            elif bit == zero:
                self.sleep_random_time_ms(delay_0_min, delay_0_max)
            

        packet2 = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
        send(packet2) 
        finish = time.time()
        print(len(binary_message)/(finish-start_time))
         

    def receive(self, log_file_name, port, threshold_0_min, threshold_0_max, threshold_1_min, threshold_1_max,src_ip,dst_ip,dot,zero,one):
        """
    This function receives and decodes a covert message transmitted over a network using timing differences between packets.
    It captures packets on a specified port and processes them to determine if they represent a '0' or '1' based on timing thresholds.
    The function appends the decoded bits to a list and converts every 8 bits to a character.
    The process continues until a '.' character is detected, indicating the end of the message.
    The decoded message is then logged to a specified log file.
    """
        packets = []
        global is_dot
        last_time = 0
        is_dot = False
        def process_packet(packet):
            nonlocal last_time
            packet_string1 = ''
           
            current_time = packet.time
            if last_time == 0:
                last_time = current_time
                return
                
            difference = (current_time - last_time)
            if threshold_0_min < difference < threshold_0_max:
                packets.append(zero)
                last_time = current_time
                if(len(packets)== 8*self.i):
                    message = ''.join(packets[8*(self.i-1):8*self.i])
                    packet_string1 = ''.join(self.convert_eight_bits_to_character(message))
                    self.i = self.i+1
                if(packet_string1== '.'):
                    self.is_dot = True   
            elif threshold_1_min < difference < threshold_1_max:
                packets.append(one)
                last_time = current_time
                if(len(packets)== 8*self.i):
                    message = ''.join(packets[8*(self.i-1):8*self.i])
                    packet_string1 = ''.join(self.convert_eight_bits_to_character(message))
                    self.i = self.i+1
                if(packet_string1== dot):
                    self.is_dot = True 
            else:
                last_time = current_time
                
                    
                
                

        sniff(
                iface="eth0",
                filter= f"tcp and src host {src_ip} and dst host {dst_ip} and port {port}",
                prn=process_packet,stop_filter= lambda packet: self.is_dot )
        
        binary_message = ''.join(packets)

        packet_string = ''.join(self.convert_eight_bits_to_character(binary_message[i:i+8]) for i in range(0, len(binary_message), 8))
        print(f"Binary message: {packet_string}")  

        self.log_message(packet_string, log_file_name)