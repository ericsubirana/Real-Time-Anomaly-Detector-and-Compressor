import struct

class AdaptiveArithmeticCodingFlows:
    def _init_(self, precision=32):
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
        Guarda los valores codificados, las probabilidades y los valores
        individuales únicos de las claves y datos en un archivo binario.
        """
        try:
            # IMPORTANTE: Usa "wb" para sobreescribir el archivo en vez de "ab" para concatenar.
            # Si necesitas mantener varios bloques, tendrías que ajustar luego la lectura.
            with open(filename, "wb") as f:
                # Escribir encabezado de 9 bytes, porque "NEW_BLOCK" tiene 9 caracteres
                f.write(b"NEW_BLOCK")

                # Guardar el valor codificado de las claves (un entero 64 bits)
                f.write(struct.pack(">Q", encoded_keys))
                print(f"Saved encoded keys: {encoded_keys}")

                # Guardar el valor codificado de los datos (un entero 64 bits)
                f.write(struct.pack(">Q", encoded_data))
                print(f"Saved encoded data: {encoded_data}")

                # Deduplicar valores individuales de las claves
                unique_key_values = list(set(value for key_ in keys for value in key_))
                print(f"Unique key values: {unique_key_values}")
                value_to_index = {value: idx for idx, value in enumerate(unique_key_values)}

                # Escribir la cantidad de valores únicos de clave
                f.write(struct.pack(">I", len(unique_key_values)))
                # Escribir los valores únicos de clave
                f.write(struct.pack(f">{len(unique_key_values)}I", *unique_key_values))
                print(f"Saved {len(unique_key_values)} unique key values.")

                # Guardar cuántas claves hay en total
                f.write(struct.pack(">I", len(keys)))
                # Guardar índices para cada clave
                for key_ in keys:
                    # 1) Escribir la longitud de la clave
                    f.write(struct.pack(">I", len(key_)))
                    # 2) Escribir los índices en base a unique_key_values
                    for v in key_:
                        f.write(struct.pack(">I", value_to_index[v]))
                print(f"Saved indices for", len(keys), "keys.")

                # Guardar cuántas probabilidades de clave tenemos
                f.write(struct.pack(">I", len(key_probabilities)))
                # Guardar (valor, probabilidad) para cada clave
                for value, prob in key_probabilities.items():
                    f.write(struct.pack(">I", value))
                    f.write(struct.pack(">f", prob))
                print(f"Saved", len(key_probabilities), "key probabilities.")

                # Deduplicar valores individuales de los datos
                unique_data_values = list(set(value for datum in data for value in datum))
                print(f"Unique data values: {unique_data_values}")
                value_to_data_index = {value: idx for idx, value in enumerate(unique_data_values)}

                # Escribir la cantidad de valores únicos de datos
                f.write(struct.pack(">I", len(unique_data_values)))
                # Escribir los valores únicos de datos
                f.write(struct.pack(f">{len(unique_data_values)}I", *unique_data_values))
                print(f"Saved", len(unique_data_values), "unique data values.")

                # Guardar cuántos datos hay en total
                f.write(struct.pack(">I", len(data)))
                # Guardar índices para cada lista de datos
                for datum in data:
                    # 1) Escribir la longitud de la lista de datos
                    f.write(struct.pack(">I", len(datum)))
                    # 2) Escribir los índices
                    for v in datum:
                        f.write(struct.pack(">I", value_to_data_index[v]))
                print(f"Saved indices for", len(data), "data.")

                # Guardar cuántas probabilidades de datos tenemos
                f.write(struct.pack(">I", len(data_probabilities)))
                # Guardar (valor, probabilidad) para cada valor de datos
                for value, prob in data_probabilities.items():
                    f.write(struct.pack(">I", value))
                    f.write(struct.pack(">f", prob))
                print(f"Saved", len(data_probabilities), "data probabilities.")
        except Exception as e:
            print(f"Error saving to file {filename}: {e}")



    def load_from_file(self, filename):
        """
        Carga TODOS los bloques que encuentre en el archivo binario y devuelve
        una lista de tuplas. Cada tupla contiene:
        (
            encoded_keys, 
            encoded_data, 
            keys, 
            data, 
            key_probabilities, 
            data_probabilities
        )
        """
        results = []
        try:
            with open(filename, "rb") as f:
                while True:
                    # 1) Leer la cabecera de 9 bytes ("NEW_BLOCK")
                    header = f.read(9)
                    if len(header) < 9:
                        # Se alcanzó EOF o el bloque está incompleto
                        break
                    if header != b"NEW_BLOCK":
                        print(f"Unexpected header: {header}")
                        break

                    # 2) Leer el valor codificado de las claves (entero de 64 bits)
                    encoded_keys = struct.unpack(">Q", f.read(8))[0]
                    print(f"Loaded encoded keys: {encoded_keys}")

                    # 3) Leer el valor codificado de los datos (entero de 64 bits)
                    encoded_data = struct.unpack(">Q", f.read(8))[0]
                    print(f"Loaded encoded data: {encoded_data}")

                    # 4) Leer los valores únicos de las claves
                    num_unique_keys = struct.unpack(">I", f.read(4))[0]
                    unique_key_values = struct.unpack(f">{num_unique_keys}I", f.read(4 * num_unique_keys))
                    print(f"Loaded {num_unique_keys} unique key values.")

                    # 5) Cargar las claves usando los índices
                    num_keys = struct.unpack(">I", f.read(4))[0]
                    keys = []
                    for _ in range(num_keys):
                        key_length = struct.unpack(">I", f.read(4))[0]
                        key_indices = struct.unpack(f">{key_length}I", f.read(4 * key_length))

                        # Validación de índices (opcional)
                        invalid_indices = [idx for idx in key_indices if idx >= len(unique_key_values)]
                        if invalid_indices:
                            print(f"Error: Invalid indices in key: {invalid_indices}")
                            continue

                        # Convertir índices a valores
                        keys.append([unique_key_values[idx] for idx in key_indices])
                    print(f"Loaded {num_keys} keys.")

                    # 6) Leer las probabilidades de las claves
                    num_key_probabilities = struct.unpack(">I", f.read(4))[0]
                    key_probabilities = {}
                    for _ in range(num_key_probabilities):
                        value = struct.unpack(">I", f.read(4))[0]
                        prob = struct.unpack(">f", f.read(4))[0]
                        key_probabilities[value] = prob
                    print(f"Loaded {num_key_probabilities} key probabilities.")

                    # 7) Leer los valores únicos de los datos
                    num_unique_data = struct.unpack(">I", f.read(4))[0]
                    unique_data_values = struct.unpack(f">{num_unique_data}I", f.read(4 * num_unique_data))
                    print(f"Loaded {num_unique_data} unique data values.")

                    # 8) Cargar los datos usando los índices
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
                    print(f"Loaded {num_data} data.")

                    # 9) Leer las probabilidades de los datos
                    num_data_probabilities = struct.unpack(">I", f.read(4))[0]
                    data_probabilities = {}
                    for _ in range(num_data_probabilities):
                        value = struct.unpack(">I", f.read(4))[0]
                        prob = struct.unpack(">f", f.read(4))[0]
                        data_probabilities[value] = prob
                    print(f"Loaded {num_data_probabilities} data probabilities.")

                    # Guardar este bloque en la lista de resultados
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