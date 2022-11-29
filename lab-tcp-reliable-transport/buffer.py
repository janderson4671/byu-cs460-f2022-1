class TCPSendBuffer(object):
    def __init__(self, seq: int):
        self.buffer = b''
        self.base_seq = seq
        self.next_seq = self.base_seq
        self.last_seq = self.base_seq

    def bytes_not_yet_sent(self):
        return self.last_seq - self.next_seq

    def bytes_outstanding(self):
        return self.next_seq - self.base_seq

    def put(self, data):
        # Append data to buffer and add to last_seq
        self.buffer = self.buffer + data
        self.last_seq = self.last_seq + len(data)

    def get(self, size):
        # Check to see if requested size exceeds buffer
        if (self.next_seq + size > self.last_seq):
            size = self.last_seq - self.next_seq
        
        index = self.next_seq - self.base_seq
        data = self.buffer[index : (index + size)]
        seq = self.next_seq

        # Update next_seq
        self.next_seq = self.next_seq + size

        return (data, seq)

    def get_for_resend(self, size):
        if (self.base_seq + size > self.last_seq):
            size = self.last_seq - self.base_seq
        
        index = 0
        data = self.buffer[index : (index + size)]
        seq = self.base_seq

        return (data, seq)

    def slide(self, sequence):

        # Calculate how much to cut off from begining of buffer
        cutoff_len = sequence - self.base_seq
        self.buffer = self.buffer[cutoff_len:]

        self.base_seq = sequence


class TCPReceiveBuffer(object):
    def __init__(self, seq: int):
        self.buffer = {}
        self.base_seq = seq

    def put(self, data, sequence):
        # Check for old data (Ignore if data is old)
        if (len(data) + sequence <= self.base_seq):
            return

        # Check for duplicate sequence number
        if (sequence in self.buffer.keys()):
            # Keep the longer of the two data sizes
            if (len(data) > len(self.buffer[sequence])):
                self.buffer[sequence] = data
            
        # Check if old data flows into new data
        elif ((sequence < self.base_seq) and (len(data) + sequence > self.base_seq)):
            # Trim off old data and store new data
            cutoff_len = (len(data) + sequence) - self.base_seq
            data = data[cutoff_len:]
            self.buffer[sequence] = data

        else:
            # add to the buffer
            self.buffer[sequence] = data

        # Run through buffer and clean up duplicates
        buffer = {}
        prev_entry = None
        for key in sorted(self.buffer.keys()):
            data = self.buffer[key]

            # Continue through first iteration
            if (prev_entry is None):
                prev_entry = (key, data)
                buffer[key] = data
                continue

            # Check whether prev_entry overflows into curr_entry
            overflow_number = prev_entry[0] + len(prev_entry[1])
            if (overflow_number >= key):
                # trim data to remove duplicate
                cutoff_len = (overflow_number) - key
                data = data[cutoff_len:]

                # Add to buffer
                buffer[overflow_number] = data
            else:
                buffer[key] = data

        # Replace old buffer with new one (That should be clean)
        self.buffer = buffer

    def get(self):

        # If there are no bytes available at the seq_base, then reutrn an empty bytes sequence
        if (self.base_seq not in self.buffer.keys()):
            return (b'', self.base_seq)
        
        sequence = b''
        removable_keys = []
        for key in sorted(self.buffer.keys()):
            data = self.buffer[key]

            # Make sure that there is no hole
            if (self.base_seq + len(sequence) != key):
                break

            # Add data to the sequence
            sequence = sequence + data
            removable_keys.append(key)
        
        ret_tuple = (sequence, self.base_seq)
        self.base_seq = self.base_seq + len(sequence)

        # Remove entries in buffer
        for key in removable_keys:
            del self.buffer[key]

        return ret_tuple

