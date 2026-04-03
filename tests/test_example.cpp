// Include decryption implementation if your smart meter uses encryption. Choose one depending on the encryption library you use.
#include "dlms_parser/decryption/aes_128_gcm_decryptor_mbedtls.h"
// #include "dlms_parser/decryption/aes_128_gcm_decryptor_bearssl.h"
// #include "dlms_parser/decryption/aes_128_gcm_decryptor_tfpsa.h"

// Include the main parser header
#include "dlms_parser/dlms_parser.h"

#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>

// Dummy functions to make the example compile
long millis() { return 0; }
struct Uart {
  size_t available() { return 0; }
  uint8_t readByte() { return 0; }
};

std::array<uint8_t, 2000> dlms_packet_buffer; // Buffer to store the incoming bytes from the smart meter
size_t dlms_packet_buffer_position = 0;       // Needed to accumulate bytes

// Decryptor instance. Only needed if your smart meter uses encryption.
// Choose the implementation depending on the encryption library.
// Available implementations:
//   * Aes128GcmDecryptorMbedTls
//   * Aes128GcmDecryptorBearSsl
//   * Aes128GcmDecryptorTfPsa
dlms_parser::Aes128GcmDecryptorMbedTls decryptor;

// The decryption key is unique per smart meter and must be provided by the electricity company.
const auto decryption_key = dlms_parser::Aes128GcmDecryptionKey::from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").value();
// The authentication key is unique per smart meter and must be provided by the electricity company.
// It is only needed if your smart meter uses authenticated encryption.
const auto authentication_key = dlms_parser::Aes128GcmAuthenticationKey::from_hex("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").value();

long last_read_timestamp = 0; // Timestamp of the last byte received. Needed to detect inter-frame gaps.

Uart uart; // UART connected to the smart meter.

dlms_parser::DlmsParser parser(&decryptor); // DLMS parser instance.

// Before you can use the parser, you need to configure it.
inline void configure_parser() {
  parser.set_decryption_key(decryption_key);
  parser.set_authentication_key(authentication_key);
  parser.load_default_patterns();

  // Set logging function if you want to capture logs. By default, the parser does not log anything.
  dlms_parser::Logger::set_log_function([](const dlms_parser::LogLevel log_level, const char* fmt, va_list args) {
    std::string level_str;
    switch (log_level) {
    case dlms_parser::LogLevel::DEBUG:        level_str = "[DBG] "; break;
    case dlms_parser::LogLevel::VERY_VERBOSE: level_str = "[VV]  "; break;
    case dlms_parser::LogLevel::VERBOSE:      level_str = "[VRB] "; break;
    case dlms_parser::LogLevel::INFO:         level_str = "[INF] "; break;
    case dlms_parser::LogLevel::WARNING:      level_str = "[WRN] "; break;
    case dlms_parser::LogLevel::ERROR:        level_str = "[ERR] "; break;
    default: throw std::runtime_error("Unknown log level");
    }
    vprintf((level_str + fmt).c_str(), args);
  });
}

// Main loop that reads data from the smart meter and parses it.
inline void loop() {
  // To receive packets, we need to rely on the inter-frame delay.
  // The smart meter transmits packets at a specific time interval (e.g., every 10 seconds).

  while (uart.available()) {
    // Reset buffer on overflow.
    if (dlms_packet_buffer_position >= dlms_packet_buffer.size()) {
      dlms_packet_buffer_position = 0;
    }

    dlms_packet_buffer[dlms_packet_buffer_position] = uart.readByte();
    dlms_packet_buffer_position++;

    // Save the timestamp of the last received byte.
    last_read_timestamp = millis();
  }

  // Detect inter-frame delay. If no byte is received for more than 1 second, the packet is complete.
  if ((millis() - last_read_timestamp) > 1000 && dlms_packet_buffer_position > 0) {
    const size_t frame_len = dlms_packet_buffer_position; // Save length before resetting.
    dlms_packet_buffer_position = 0; // Reset for the next packet.

    // Define a callback that will be called by the DlmsParser for every parsed value.
    auto on_value = [](const char* obis_code, float float_val, const char* str_val, bool is_numeric) {
      if (is_numeric) {
        printf("%s = %.3f\n", obis_code, static_cast<double>(float_val));
      }
      else {
        printf("%s = '%s'\n", obis_code, str_val);
      }
    };

    auto [objects_found, bytes_consumed] = parser.parse({dlms_packet_buffer.data(), frame_len}, on_value);
    printf("%zu objects found\n", objects_found);
  }
}
