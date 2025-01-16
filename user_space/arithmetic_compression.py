import struct

class AdaptiveArithmeticCodingFlows:
    def __init__(self, precision=32):
        self.precision = precision
        self.max_range = (1 << self.precision) - 1
        self.mask = self.max_range
        self.key_frequencies = {}
        self.data_frequencies = {}

    def calculate_probabilities(self, frequencies):
        total_count = sum(frequencies.values())
        if total_count == 0:
            return {}
        return {k: v / total_count for k, v in frequencies.items()}

    def update_frequencies(self, data, frequency_table):
        for value in data:
            frequency_table[value] = frequency_table.get(value, 0) + 1

    def encode(self, serialized_data, probabilities):
        """
        Codifica serialized_data utilizando las probabilidades de cada elemento individual.
        """
        # Inicializar los límites
        low = 0
        high = self.max_range
        cumulative_prob = self._build_cumulative_probabilities(probabilities)

        # Iterar sobre cada tupla en serialized_data
        for data_tuple in serialized_data:
            for value in data_tuple:  # Procesar cada elemento de la tupla
                if value not in cumulative_prob:
                    raise ValueError(f"Value {value} not in cumulative probabilities")

                # Calcular el rango para el valor actual
                range_width = high - low + 1
                prob_low, prob_high = cumulative_prob[value]
                high = low + int(range_width * prob_high) - 1
                low = low + int(range_width * prob_low)

                # Normalizar cuando los bits más significativos coinciden
                while (high & self.mask) == (low & self.mask):
                    low = (low << 1) & self.mask
                    high = ((high << 1) & self.mask) | 1

        print(f"Encoded range: low={low}, high={high}")
        return low

    def decode(self, encoded_value, probabilities, data_length):
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
        cumulative_prob = {}
        cumulative = 0.0
        for symbol, prob in sorted(probabilities.items()):
            cumulative_prob[symbol] = (cumulative, cumulative + prob)
            cumulative += prob
        return cumulative_prob

    def save_to_file(self, filename, encoded_keys, encoded_data, keys, data, key_probabilities, data_probabilities):
        """
        Guarda los valores codificados, las probabilidades y los valores individuales únicos de las claves y datos en un archivo binario.
        """
        try:
            with open(filename, "ab") as f:
                # Escribir encabezado
                f.write(b"NEW_BLOCK")

                # Guardar el valor codificado de las claves
                f.write(struct.pack(">Q", encoded_keys))
                print(f"Saved encoded keys: {encoded_keys}")

                # Guardar el valor codificado de los datos
                f.write(struct.pack(">Q", encoded_data))
                print(f"Saved encoded data: {encoded_data}")

                # Deduplicar valores individuales de las claves
                unique_key_values = list(set(value for key in keys for value in key))  # Extraer valores individuales únicos
                print(f"Unique key values: {unique_key_values}")  # Verifica los valores únicos de las claves
                value_to_index = {value: idx for idx, value in enumerate(unique_key_values)}

                # Comprobar que todos los valores en las claves estén en los valores únicos
                for key in keys:
                    for value in key:
                        if value not in value_to_index:
                            print(f"Warning: Value {value} from key {key} not found in unique key values.")

                f.write(struct.pack(">I", len(unique_key_values)))  # Número de valores únicos
                f.write(struct.pack(f">{len(unique_key_values)}I", *unique_key_values))  # Guardar los valores únicos
                print(f"Saved {len(unique_key_values)} unique key values.")

                # Guardar índices para reconstruir las claves
                f.write(struct.pack(">I", len(keys)))  # Número de claves
                for key in keys:
                    f.write(struct.pack(f">{len(key)}I", *(value_to_index[v] for v in key)))  # Usar índice de los valores
                print(f"Saved indices for {len(keys)} keys.")

                # Guardar probabilidades de las claves
                f.write(struct.pack(">I", len(key_probabilities)))  # Número de probabilidades de claves
                for value, prob in key_probabilities.items():
                    f.write(struct.pack(">I", value))  # Valor individual
                    f.write(struct.pack(">f", prob))  # Probabilidad
                print(f"Saved {len(key_probabilities)} key probabilities.")

                # Deduplicar valores individuales de los datos (similar a las claves)
                unique_data_values = list(set(value for datum in data for value in datum))  # Extraer valores individuales únicos
                print(f"Unique data values: {unique_data_values}")  # Verifica los valores únicos de los datos
                value_to_data_index = {value: idx for idx, value in enumerate(unique_data_values)}

                # Comprobar que todos los valores en los datos estén en los valores únicos
                for datum in data:
                    for value in datum:
                        if value not in value_to_data_index:
                            print(f"Warning: Value {value} from data {datum} not found in unique data values.")

                f.write(struct.pack(">I", len(unique_data_values)))  # Número de valores únicos
                f.write(struct.pack(f">{len(unique_data_values)}I", *unique_data_values))  # Guardar los valores únicos
                print(f"Saved {len(unique_data_values)} unique data values.")

                # Guardar índices para reconstruir los datos
                f.write(struct.pack(">I", len(data)))  # Número de datos
                for datum in data:
                    f.write(struct.pack(f">{len(datum)}I", *(value_to_data_index[v] for v in datum)))  # Usar índice de los valores
                print(f"Saved indices for {len(data)} data.")

                # Guardar probabilidades de los datos
                f.write(struct.pack(">I", len(data_probabilities)))  # Número de probabilidades de datos
                for value, prob in data_probabilities.items():
                    f.write(struct.pack(">I", value))  # Valor individual
                    f.write(struct.pack(">f", prob))  # Probabilidad
                print(f"Saved {len(data_probabilities)} data probabilities.")
        except Exception as e:
            print(f"Error saving to file {filename}: {e}")

    def load_from_file(self, filename):
        """
        Carga los valores codificados, las probabilidades y los valores únicos de las claves y los datos desde un archivo binario.
        """
        try:
            with open(filename, "rb") as f:
                # Leer encabezado
                header = f.read(9)  # Se espera que la longitud del encabezado sea 8 bytes
                if header != b"NEW_BLOCK":
                    print(f"Unexpected header: {header}")
                    return

                # Leer el valor codificado de las claves
                encoded_keys = struct.unpack(">Q", f.read(8))[0]
                print(f"Loaded encoded keys: {encoded_keys}")

                # Leer el valor codificado de los datos
                encoded_data = struct.unpack(">Q", f.read(8))[0]
                print(f"Loaded encoded data: {encoded_data}")

                # Leer los valores únicos de las claves
                num_unique_keys = struct.unpack(">I", f.read(4))[0]
                unique_key_values = struct.unpack(f">{num_unique_keys}I", f.read(4 * num_unique_keys))
                print(f"Loaded unique key values: {unique_key_values}")

                # Leer los índices de las claves
                num_keys = struct.unpack(">I", f.read(4))[0]
                keys = []
                for i in range(num_keys):
                    num_values_in_key = struct.unpack(">I", f.read(4))[0]
                    key_indices = struct.unpack(f">{num_values_in_key}I", f.read(4 * num_values_in_key))

                    # Validación de índices
                    invalid_indices = [idx for idx in key_indices if idx >= len(unique_key_values)]
                    if invalid_indices:
                        print(f"Error: Invalid indices in key {i}: {invalid_indices}")
                        continue  # O puedes lanzar una excepción si prefieres detener el proceso

                    keys.append([unique_key_values[idx] for idx in key_indices])
                print(f"Loaded {num_keys} keys.")

                # Leer las probabilidades de las claves
                num_key_probabilities = struct.unpack(">I", f.read(4))[0]
                key_probabilities = {}
                for _ in range(num_key_probabilities):
                    value = struct.unpack(">I", f.read(4))[0]
                    prob = struct.unpack(">f", f.read(4))[0]
                    key_probabilities[value] = prob
                print(f"Loaded {num_key_probabilities} key probabilities.")

                # Leer los valores únicos de los datos
                num_unique_data = struct.unpack(">I", f.read(4))[0]
                unique_data_values = struct.unpack(f">{num_unique_data}I", f.read(4 * num_unique_data))
                print(f"Loaded unique data values: {unique_data_values}")

                # Leer los índices de los datos
                num_data = struct.unpack(">I", f.read(4))[0]
                data = []
                for i in range(num_data):
                    num_values_in_datum = struct.unpack(">I", f.read(4))[0]
                    datum_indices = struct.unpack(f">{num_values_in_datum}I", f.read(4 * num_values_in_datum))

                    # Validación de índices
                    invalid_indices = [idx for idx in datum_indices if idx >= len(unique_data_values)]
                    if invalid_indices:
                        print(f"Error: Invalid indices in data {i}: {invalid_indices}")
                        continue  # O puedes lanzar una excepción si prefieres detener el proceso

                    data.append([unique_data_values[idx] for idx in datum_indices])
                print(f"Loaded {num_data} data.")

                # Leer las probabilidades de los datos
                num_data_probabilities = struct.unpack(">I", f.read(4))[0]
                data_probabilities = {}
                for _ in range(num_data_probabilities):
                    value = struct.unpack(">I", f.read(4))[0]
                    prob = struct.unpack(">f", f.read(4))[0]
                    data_probabilities[value] = prob
                print(f"Loaded {num_data_probabilities} data probabilities.")
        except Exception as e:
            print(f"Error loading from file {filename}: {e}")

    def _serialize_flow_key(self, flow_key):
        # Serializa un FlowKey para la compresión
        return [
            flow_key.src_ip,
            flow_key.dst_ip,
            flow_key.src_port,
            flow_key.dst_port,
            flow_key.protocol
        ]

    def _serialize_flow_data(self, flow_data):
        # Serializa un FlowData para la compresión
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
