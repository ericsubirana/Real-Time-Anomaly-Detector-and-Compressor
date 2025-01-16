import struct

class AdaptiveArithmeticCodingFlows:
    """
    Implements adaptive arithmetic coding for flow data compression.
    Serialization and frequency updates are provided for flow keys and flow data.
    """
    def __init__(self, precision=64):
        self.precision = precision
        self.max_range = (1 << self.precision) - 1
        self.mask = self.max_range
        self.key_frequencies = {}
        self.data_frequencies = {}

    def calculate_probabilities(self, frequencies):
        """
        Convert a frequency table into probability ranges.
        """
        total_count = sum(frequencies.values())
        if total_count == 0:
            return {}
        return {k: v / total_count for k, v in frequencies.items()}

    def update_frequencies(self, data, frequency_table):
        """
        Update frequency counts for each value in 'data'.
        """
        for value in data:
            frequency_table[value] = frequency_table.get(value, 0) + 1

    def encode(self, serialized_data, probabilities):
        """
        Encodes 'serialized_data' using the provided probabilities.
        Each item in 'serialized_data' may be a tuple representing a flow key or flow data.
        """
        low = 0
        high = self.max_range
        cumulative_prob = self._build_cumulative_probabilities(probabilities)

        for data_tuple in serialized_data:
            for value in data_tuple:  
                if value not in cumulative_prob:
                    raise ValueError(f"Value {value} not in cumulative probabilities")

                range_width = high - low + 1
                prob_low, prob_high = cumulative_prob[value]
                high = low + int(range_width * prob_high) - 1
                low = low + int(range_width * prob_low)

                while (high & self.mask) == (low & self.mask):
                    low = (low << 1) & self.mask
                    high = ((high << 1) & self.mask) | 1

        print(f"Encoded range: low={low}, high={high}")
        return low

    def decode(self, encoded_value, probabilities, data_length):
        """
        Decodes an encoded value given the probability table and the
        number of symbols (data_length) to decode.
        """
        low = 0
        high = self.max_range
        cumulative_prob = self._build_cumulative_probabilities(probabilities)
        decoded_data = []

        for _ in range(data_length):
            range_width = high - low + 1
            scaled_value = ((encoded_value - low + 1) * 1.0) / range_width

            for symbol, (prob_low, prob_high) in cumulative_prob.items():
                if prob_low <= scaled_value < prob_high:
                    decoded_data.append(symbol)
                    high = low + int(range_width * prob_high) - 1
                    low = low + int(range_width * prob_low)
                    break
            else:
                raise ValueError("Decoded symbol not found")

            while (high & self.mask) == (low & self.mask):
                low = (low << 1) & self.mask
                high = ((high << 1) & self.mask) | 1

        return decoded_data

    def _build_cumulative_probabilities(self, probabilities):
        """
        Construct cumulative probability intervals for each symbol.
        """
        cumulative_prob = {}
        cumulative = 0.0
        for symbol, prob in sorted(probabilities.items()):
            cumulative_prob[symbol] = (cumulative, cumulative + prob)
            cumulative += prob
        return cumulative_prob

    def save_to_file(self, filename, encoded_keys, encoded_data, keys, data, key_probabilities, data_probabilities):
        """
        Saves the encoded values (keys and data), along with probabilities and
        the original unique values, to a binary file.
        """
        try:
            
            with open(filename, "ab") as f:
                f.write(b"NEW_BLOCK")

                f.write(struct.pack(">Q", encoded_keys))
                print(f"Saved encoded keys: {encoded_keys}")

                f.write(struct.pack(">Q", encoded_data))
                print(f"Saved encoded data: {encoded_data}")

                unique_key_values = list(set(value for key_ in keys for value in key_))
                value_to_index = {value: idx for idx, value in enumerate(unique_key_values)}

                # Write key probabilities
                f.write(struct.pack(">I", len(unique_key_values)))
                # Gather unique data values and write them
                f.write(struct.pack(f">{len(unique_key_values)}I", *unique_key_values))
                f.write(struct.pack(">I", len(keys)))

                for key_ in keys:
                    f.write(struct.pack(">I", len(key_)))
                    for v in key_:
                        f.write(struct.pack(">I", value_to_index[v]))

                
                f.write(struct.pack(">I", len(key_probabilities)))
               
                for value, prob in key_probabilities.items():
                    f.write(struct.pack(">I", value))
                    f.write(struct.pack(">f", prob))

                unique_data_values = list(set(value for datum in data for value in datum))
                value_to_data_index = {value: idx for idx, value in enumerate(unique_data_values)}

                f.write(struct.pack(">I", len(unique_data_values)))
                f.write(struct.pack(f">{len(unique_data_values)}I", *unique_data_values))

                f.write(struct.pack(">I", len(data)))
                for datum in data:
                    f.write(struct.pack(">I", len(datum)))
                    for v in datum:
                        f.write(struct.pack(">I", value_to_data_index[v]))

                f.write(struct.pack(">I", len(data_probabilities)))
                for value, prob in data_probabilities.items():
                    f.write(struct.pack(">I", value))
                    f.write(struct.pack(">f", prob))
        except Exception as e:
            None



    def load_from_file(self, filename):
        """
        Loads ALL blocks from the specified binary file. Returns a list of tuples:
          (encoded_keys, encoded_data, keys, data, key_probabilities, data_probabilities)
        Each tuple corresponds to one "NEW_BLOCK" in the file.
        """
        results = []
        try:
            with open(filename, "rb") as f:
                while True:
                    header = f.read(9)
                    if len(header) < 9:
                        break
                    if header != b"NEW_BLOCK":
                        print(f"Unexpected header: {header}")
                        break

                    encoded_keys = struct.unpack(">Q", f.read(8))[0]

                    encoded_data = struct.unpack(">Q", f.read(8))[0]

                    # Unique key values
                    num_unique_keys = struct.unpack(">I", f.read(4))[0]
                    unique_key_values = struct.unpack(f">{num_unique_keys}I", f.read(4 * num_unique_keys))

                    # Reconstruct keys from indices
                    num_keys = struct.unpack(">I", f.read(4))[0]
                    keys = []
                    for _ in range(num_keys):
                        key_length = struct.unpack(">I", f.read(4))[0]
                        key_indices = struct.unpack(f">{key_length}I", f.read(4 * key_length))

                        invalid_indices = [idx for idx in key_indices if idx >= len(unique_key_values)]
                        if invalid_indices:
                            print(f"Error: Invalid indices in key: {invalid_indices}")
                            continue

                        keys.append([unique_key_values[idx] for idx in key_indices])

                    num_key_probabilities = struct.unpack(">I", f.read(4))[0]
                    key_probabilities = {}
                    for _ in range(num_key_probabilities):
                        value = struct.unpack(">I", f.read(4))[0]
                        prob = struct.unpack(">f", f.read(4))[0]
                        key_probabilities[value] = prob

                    num_unique_data = struct.unpack(">I", f.read(4))[0]
                    unique_data_values = struct.unpack(f">{num_unique_data}I", f.read(4 * num_unique_data))

                    num_data = struct.unpack(">I", f.read(4))[0]
                    data = []
                    for _ in range(num_data):
                        data_length = struct.unpack(">I", f.read(4))[0]
                        data_indices = struct.unpack(f">{data_length}I", f.read(4 * data_length))

                        invalid_indices = [idx for idx in data_indices if idx >= len(unique_data_values)]
                        if invalid_indices:
                            print(f"Error: Invalid indices in data: {invalid_indices}")
                            continue

                        data.append([unique_data_values[idx] for idx in data_indices])

                    num_data_probabilities = struct.unpack(">I", f.read(4))[0]
                    data_probabilities = {}
                    for _ in range(num_data_probabilities):
                        value = struct.unpack(">I", f.read(4))[0]
                        prob = struct.unpack(">f", f.read(4))[0]
                        data_probabilities[value] = prob

                    results.append((encoded_keys,
                                    encoded_data,
                                    keys,
                                    data,
                                    key_probabilities,
                                    data_probabilities))

        except Exception as e:
            print(f"Error loading from file {filename}: {e}")

        # Devolver todos los bloques leídos
        return results


    def _serialize_flow_key(self, flow_key):
        """
        Serialize a FlowKey structure into a list of integers for compression.
        """
        return [
            flow_key.src_ip,
            flow_key.dst_ip,
            flow_key.src_port,
            flow_key.dst_port,
            flow_key.protocol
        ]

    def _serialize_flow_data(self, flow_data):
        """
        Serialize a FlowData structure into a list of integers for compression.
        """
        return [
            flow_data.first_seen,
            flow_data.last_seen,
            flow_data.packet_count,
            flow_data.byte_count,
            flow_data.fwd_packet_count,
            flow_data.bwd_packet_count,
            flow_data.fwd_byte_count,
            flow_data.bwd_byte_count,
            flow_data.min_packet_length,
            flow_data.max_packet_length,
            flow_data.syn_count,
            flow_data.ack_count,
            flow_data.psh_count,
            flow_data.urg_count,
        ]