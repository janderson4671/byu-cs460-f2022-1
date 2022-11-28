class TCPSendBuffer(object):
    def __init__(self, seq):
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
    def __init__(self, seq):
        self.buffer = {}
        self.base_seq = seq

    def put(self, data, sequence):
        pass

    def get(self):
        pass
