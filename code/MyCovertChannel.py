from CovertChannelBase import CovertChannelBase
import random, time
from scapy.all import IP, TCP, sniff

class MyCovertChannel(CovertChannelBase):
    
    """
    Covert Timing Channel that exploits Idle Period Between Packet Bursts using TCP [Code: CTC-IPPB-TCP]
Responses: 0
Limit: 1
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        super().__init__()
        self.random = random
        self.is_dot = False
        self.i = 1 
        
    def send(self, log_file_name, src_ip, dst_ip, dst_port, min_packets, max_packets, delay_1_min, delay_1_max, delay_0_min, delay_0_max):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        "creates random binary message and then goes through each bit of this message. For each bit it generates a random number of packets and sends them to receiver."
        "whether bit is 0 or 1 delay is changed of the burst therefore on receiver side we can understand if its 0 or 1 based on the delay"
        
        binary_message = self.generate_random_binary_message_with_logging("log_file_name")
     
        start_time = time.time()

        for bit in binary_message:
            num_packets = self.random.randint(min_packets, max_packets)
            print(f"number of packets in burst: {num_packets}")

            for i in range(num_packets):
                packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
                super().send(packet)  #  send method from CovertChannelBase
            if bit == '1':
                self.sleep_random_time_ms(delay_1_min, delay_1_max)
            elif bit == '0':
                self.sleep_random_time_ms(delay_0_min, delay_0_max)
            packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)
            super().send(packet)  #  send method from CovertChannelBase
        finish = time.time()
        print(len(binary_message)/(finish-start_time))
         

    def receive(self, log_file_name, port, threshold_0_min, threshold_0_max, threshold_1_min, threshold_1_max):
        packets = []
        global is_dot
        last_time = 0
        is_dot = False
        def process_packet(packet):
            nonlocal last_time
            packet_string1 = ''
            if packet.haslayer(TCP) and packet[IP].src == "172.18.0.2" and packet[IP].dst == "172.18.0.3":
                current_time = packet.time
                if last_time == 0:
                    last_time = current_time
                    print(f"Packet time: {current_time:.5f}")  
                    return
                print(current_time-last_time)
                
                difference = (current_time - last_time)
                print(f"Packet time: {current_time:.5f}, Last time: {last_time:.5f}, Difference: {difference:.5f} seconds") 
                if threshold_0_min < difference < threshold_0_max:
                    packets.append('0')
                    last_time = current_time
                    print("Appended 0")
                    print(len(packets))
                    if(len(packets)== 8*self.i):
                        print("YO")
                        message = ''.join(packets[8*(self.i-1):8*self.i])
                        packet_string1 = ''.join(self.convert_eight_bits_to_character(message))
                        print(packet_string1)
                        self.i = self.i+1
                    if(packet_string1== '.'):
                        self.is_dot = True   
                elif threshold_1_min < difference < threshold_1_max:
                    packets.append('1')
                    last_time = current_time
                    print("Appended 1")
                    print(len(packets))
                    if(len(packets)== 8*self.i):
                        print("YO")
                        message = ''.join(packets[8*(self.i-1):8*self.i])
                        packet_string1 = ''.join(self.convert_eight_bits_to_character(message))
                        print(packet_string1)
                        self.i = self.i+1
                    if(packet_string1== '.'):
                        self.is_dot = True 
                else:
                    last_time = current_time
                
                    
                
                

        sniff(
                iface="eth0",
                filter="tcp port 8000",
                prn=process_packet,stop_filter= lambda packet: self.is_dot )
        
        print("This line will only execute AFTER sniffing stops.") 
        binary_message = ''.join(packets)

        packet_string = ''.join(self.convert_eight_bits_to_character(binary_message[i:i+8]) for i in range(0, len(binary_message), 8))
        print(f"Binary message: {packet_string}")  # Debugging line to check the binary message

        self.log_message(packet_string, log_file_name)