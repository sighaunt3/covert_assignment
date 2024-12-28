# Covert Timing Channel that exploits Idle Period Between Packet Bursts using TCP [Code: CTC-IPPB-TCP]



## Project Description
This project implements a covert timing channel that exploits idle periods between packet bursts using TCP. The covert channel is designed to send binary messages by varying the timing between packet transmissions.

### Idle Period Between Packet Bursts
This technique encodes information by varying the duration of inactivity or idle time between bursts of packets. For example, a short idle period might represent a ‘0’ and a long idle period might represent a ‘1’. The sender controls the idle times between groups of packets and the receiver decodes the data by analyzing these gaps. The receiver determines the value of the bit based on the delay between packet bursts.

The dot character is the stopping character for the covert channel communication. When the dot character is received, the entire covert channel communication finishes and the receiver stops capturing the new packets.

## Implementation
### send()
In this function, the sender encodes the binary message by varying the idle time between packet bursts. The parameters for the send function are defined in the config.json file.

#### Parameters
- log_file_name: The name of the log file where the binary message will be saved.
- src_ip: The source IP address for the packets.
- dst_ip: The destination IP address for the packets.
- dst_port: The destination port for the packets.
- min_packets: The minimum number of packets to send in each burst.
- max_packets: The maximum number of packets to send in each burst.
- delay_0_min: The minimum delay (in seconds) between bursts representing a '0' bit.
- delay_0_max: The maximum delay (in seconds) between bursts representing a '0' bit.
- delay_1_min: The minimum delay (in seconds) between bursts representing a '1' bit.
- delay_0_max: The maximum delay (in seconds) between bursts representing a '1' bit.

#### Process
1. A binary message of length 128 bits is generated and logged to the sender.log file.
2. The timer is started just before sending the first packet which will be used to calculate the bits per second of the implementation.
3. For each bit in the binary message a random number of packets is generated based on the random library. The amount generated is based on the parameter min_packets and max_packets. For the number of packets determined a new packet is added to the packet_list. Once the number of packets determined has been achieved in the packet_list, these packets are sent together via the send method of CovertChannelBase class. If the bit is '0', the sender waits for a random delay_0_min to delay_0_max seconds before sending the next burst. If the bit is '1', the sender waits for a random delay_1_min to delay_1_max seconds before sending the next burst. This process is then repeated for each bit in binary_message. Once all bits have been traversed a dummy packet is sent out. The dummy packet is necessary as the receiver side functions by checking the delay from the current bit to the previous bit. In order for the terminating character '.' to be read there needs to be an extra packet received which allows for the comparison of the delay between the dummy bit and the last real bit allowing for the receiver to determine if its a 0 or 1.

4. *End Timer*: The timer is stopped just after sending the last packet.
5. *Calculate Capacity*: The covert channel capacity is calculated as the number of bits (128) divided by the time taken to send the message, resulting in bits per second.
6. *Log Capacity*: The calculated covert channel capacity is printed to the console.

This method ensures that the binary message is encoded in the timing between packet bursts, allowing the receiver to decode the message by analyzing these intervals.


### receive()
In this function, the receiver decodes the transferred message by analyzing the time intervals between packet bursts. The parameters for the receive function are defined in the config.json file.

#### Parameters
- log_file_name: The name of the log file where the decoded message will be saved.
- port: The destination port for the packets.
- threshold_0_min: The minimum threshold (in seconds) for detecting a '0' bit.
- threshold_0_max: The maximum threshold (in seconds) for detecting a '0' bit.
- threshold_1_min: The minimum threshold (in seconds) for detecting a '1' bit.
- threshold_1_max: The maximum threshold (in seconds) for detecting a '1' bit.

#### Process
1. *Initialize Variables*: Initialize variables to store the packets, the last packet time and a flag to indicate when the dot character is received.
2. *Process Packets*: Use the sniff function from Scapy to capture packets and process each packet. Whenever a new packet is captured that meets the filter requirements, process_packets function is invoked. Inside the process_packets function there are 2 important variables. Current time variable is the current time of the this packet while last_time is the time of arrival of the last packet. If the difference between these packets are negligable that means that they are part of the same packet burst meaning the delay between them wont help us determine whether the bit is a 0 or 1. If last_time equal zero, this indicates that this is the first packet received which means that no calculation is necessary due to this the last_time is set to current_time. Otherwise the we find the difference between last_time and current_time if this value is not within the threshold for 0 or for the threshold for 1 then we assume that its within the same packet burst and we just set the last_time variable as the current_time. The thresholds for each bit is determined based on the inherent network delay that comes with the send() alongside the delay we impose to determine if the bit is 0 or 1. Due to this, the thresholds have to account for the delays added on by us alongside the delays caused by the network. For examples threshold_0_min will equal delay_0_min while threshold_0_max will equal delay_0_max + network delay. This is ultimately what allows us to ignore packets that are in the same burst and determine whether the time difference between packet burst indicate a 0 or 1. If the difference is within a given threshold that bit to which its in the threshold for is appended to packet_list. packet_list collects every single bit inside of it and at the end of the receive function is the message that is decoded. Due to the fact that there is a terminating character '.' , after appending each element to packet_list we check if the current number of elements inside of this list is multiple of 8 as binary messages are 8 0 or 1's that have come together. If its not a multiple of 8, last_time is just set as current_time and we continue. However, if its a multiple of 8 then we convert the last 8 bits into a character and check if this character equals '.'. If it equals '.'  is_dot is set to true. For the sniff function the is_dot returning true results in the sniff function to stop working and no more packets are received. Once is_dot becomes true the the packets list is joined together to form a binary message which is then decoded. This decoded message is saved to receiver.log 

This method ensures that the binary message is decoded by analyzing the timing between packet bursts, allowing the receiver to reconstruct the original message.


## Covert Channel Capacity
To measure the covert channel capacity, a binary message of length 128 bits (16 characters) was sent. The time taken to send the message was measured and the capacity was calculated as follows:

1. A binary message of length 128 bits created (contains 16 characters).
2. Start the timer just before sending the first packet.
3. Finish the timer just after sending the last packet.
4. Calculate the time difference in seconds.
5. Divide 128 by the calculated time in seconds to get the capacity in bits per second.

The covert channel capacity is approximately *2.32 bits per second*.

## Limitations
- The minimum delay for sending a '0' bit is set to delay_0_min (0.23 seconds). While the maximum is set to delay_0_max (0.26 seconds).
- The minimum delay for sending a '1' bit is set to delay_1_min (0.5 seconds). While the maximum is set to delay_1_max (0.51 seconds).
- The thresholds for detecting '0' bit on the receiver side is defined by threshold_0_min (0.23 seconds) and threshold_0_max (delay_0_max(0.26) + possible network delay(0.23) = 0.49 seconds).
- The thresholds for detecting '1' bit on the receiver side is defined by threshold_1_min (0.5 seconds) and threshold_1_max (delay_1_max(0.51) + possible network delay(0.29) = 0.80 seconds).


The minumum delay is set 0.23 seconds because from our observations there is a varying network delay in the implementation. This ranges from 0.07 to 0.22 seconds. To get around this and ensure consistency the minumum delay for sending a bit must be greater than the greatest amount of network delay in order to ensure the implementation doesn't confuse normal network delay with a packet indicating a 0 or 1. To get around this, all the delays imposed on this implementation are greater than the maximum network delay we observed. For the threshold side the thresholds have to account for the delay_0_max or delay_1_max + the maximum amount of network delay. As network delay can occur while sending the packet indicating a 0 or 1. In order to not lose data in this case the thresholds have been accounted for accordingly.

We set the minimum delay for 0 bit as 0.23 seconds as this is the lowest we can have while still being above the maximum network delay. We set the maximum delay to 0.26 seconds since we didn not want to add too much delay which would make the process slower.

We set the minumum delay for 1 bit as 0.5 as the threshold for detecting 0 bit can go up 0.47 and this is the lowest numbers we can assign while being above that range. We set the maximum delay to 0.51 seconds since we did not want to add too much delay which would make the process slower.

We set the thresholds for 0 bit and 1 bit by taking their minimum delay value and adjusting the maximum delay to account for the network delay.

Ultimately, due to the fact that multiple packets are sent for each bit, the implementation is deeply impacted by network delay which results in us to make use of very large delay in order to prevent any data corruption

## Usage
To run the sender and receiver, use the following commands:

# Start the receiver
make receive

# Start the sender
make send
