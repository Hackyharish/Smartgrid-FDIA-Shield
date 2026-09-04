/*
 * MODULE BRIEFING
 * File: smartgrid_node.ino
 * Purpose: ESP32 Firmware for IoT-Based False Data Injection Attack Detection and Data Recovery
 * Target: ESP32 WROOM-32 (Arduino IDE 2.x)
 * 
 * Dependencies (Install via Arduino Library Manager):
 * - WiFi.h (built-in ESP32)
 * - PubSubClient by Nick O'Leary
 * - ArduinoJson by Benoit Blanchon (v6)
 * - NTPClient by Fabrice Weinberg
 * - WiFiUdp.h (built-in)
 * - mbedtls/md.h (built-in ESP32 for HMAC)
 * - HardwareSerial (built-in)
 * 
 * Hardware:
 * - ESP32 WROOM-32
 * - PZEM-004T v3.0 connected to UART2 (RX: GPIO16, TX: GPIO17)
 * 
 * Disclaimer: Attack simulation commands (FDI, FREEZE) are intended STRICTLY 
 * for educational lab testbed environments to evaluate detection algorithms.
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <NTPClient.h>
#include <HardwareSerial.h>
#include "mbedtls/md.h"

// ==============================================================================
// SECTION 1 — Configuration
// ==============================================================================
const char* WIFI_SSID = "YOUR_SSID";
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* MQTT_SERVER = "192.168.1.100";
const int MQTT_PORT = 1883;
const char* NODE_ID = "node_01";
const char* HMAC_SECRET_KEY = "smartgrid_secret_key_2025";
const int PUBLISH_INTERVAL_MS = 5000;

IPAddress staticIP(192, 168, 1, 101);
IPAddress gateway(192, 168, 1, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress dns(8, 8, 8, 8);

const char* MQTT_TOPIC_PUB = "smartgrid/node01/telemetry";
const char* MQTT_TOPIC_SUB = "smartgrid/node01/cmd";

// ==============================================================================
// Globals & Objects
// ==============================================================================
WiFiClient espClient;
PubSubClient mqtt(espClient);
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, "pool.ntp.org", 0, 21600000); // Sync every 6 hours

HardwareSerial pzemSerial(2);

unsigned long lastPublishTime = 0;
uint32_t sequenceNumber = 0;
uint32_t crcErrorCount = 0;

// ==============================================================================
// SECTION 7 — Attack Simulation Command Handler (State variables)
// ==============================================================================
volatile bool attackFdiActive = false;
volatile float fdiVoltageScale = 1.0;
volatile float fdiCurrentScale = 1.0;
volatile unsigned long attackEndTime = 0;

volatile bool attackFreezeActive = false;
volatile unsigned long freezeEndTime = 0;
float frozenVoltage = 0.0, frozenCurrent = 0.0, frozenPower = 0.0, frozenEnergy = 0.0;
float frozenFreq = 0.0, frozenPf = 0.0;

// ==============================================================================
// SECTION 3 — PZEM-004T Modbus-RTU helper functions
// ==============================================================================
uint16_t calculateCRC(const uint8_t *data, uint16_t length) {
  uint16_t crc = 0xFFFF;
  for (uint16_t pos = 0; pos < length; pos++) {
    crc ^= (uint16_t)data[pos];
    for (int i = 8; i != 0; i--) {
      if ((crc & 0x0001) != 0) {
        crc >>= 1;
        crc ^= 0xA001;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc;
}

struct PzemData {
  float voltage;
  float current;
  float power;
  float energy;
  float frequency;
  float pf;
  uint16_t alarm;
  bool valid;
};

PzemData readPzem();

PzemData readPzem() {
  PzemData data = {0, 0, 0, 0, 0, 0, 0, false};
  
  uint8_t reqFrame[] = {0x01, 0x04, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00};
  uint16_t reqCrc = calculateCRC(reqFrame, 6);
  reqFrame[6] = reqCrc & 0xFF;
  reqFrame[7] = (reqCrc >> 8) & 0xFF;

  for (int attempt = 0; attempt < 3; attempt++) {
    while (pzemSerial.available()) pzemSerial.read(); // clear buffer
    pzemSerial.write(reqFrame, sizeof(reqFrame));
    pzemSerial.flush();

    unsigned long startTime = millis();
    uint8_t buf[25];
    int idx = 0;

    while (millis() - startTime < 500) {
      if (pzemSerial.available()) {
        buf[idx++] = pzemSerial.read();
        if (idx == 25) break;
      }
    }

    if (idx == 25) {
      uint16_t recCrc = buf[23] | (buf[24] << 8);
      uint16_t calcCrc = calculateCRC(buf, 23);
      if (recCrc == calcCrc) {
        data.voltage = ((buf[3] << 8) | buf[4]) / 10.0;
        
        // bytes 5-6 = low word, 7-8 = high word
        uint32_t currentRaw = (buf[7] << 24) | (buf[8] << 16) | (buf[5] << 8) | buf[6];
        data.current = currentRaw / 1000.0;
        
        uint32_t powerRaw = (buf[11] << 24) | (buf[12] << 16) | (buf[9] << 8) | buf[10];
        data.power = powerRaw / 10.0;
        
        uint32_t energyRaw = (buf[15] << 24) | (buf[16] << 16) | (buf[13] << 8) | buf[14];
        data.energy = energyRaw; // Wh
        
        data.frequency = ((buf[17] << 8) | buf[18]) / 10.0;
        data.pf = ((buf[19] << 8) | buf[20]) / 100.0;
        data.alarm = (buf[21] << 8) | buf[22];
        data.valid = true;
        return data;
      } else {
        crcErrorCount++;
      }
    }
  }
  return data; // Invalid
}

// ==============================================================================
// SECTION 4 — HMAC-SHA256
// ==============================================================================
String computeHMAC(const char* payload, const char* key) {
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key, strlen(key));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)payload, strlen(payload));
  
  unsigned char hmacResult[32];
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  String hashStr = "";
  for (int i = 0; i < 32; i++) {
    char hex[3];
    sprintf(hex, "%02x", hmacResult[i]);
    hashStr += hex;
  }
  return hashStr;
}

// ==============================================================================
// SECTION 7 — Attack Command Handler
// ==============================================================================
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  StaticJsonDocument<512> doc;
  DeserializationError err = deserializeJson(doc, payload, length);
  if (err) return;

  const char* cmd = doc["cmd"];
  if (!cmd) return;

  if (strcmp(cmd, "INJECT_FDI") == 0) {
    attackFdiActive = true;
    attackFreezeActive = false;
    fdiVoltageScale = doc["voltage"] | 1.0;
    fdiCurrentScale = doc["current"] | 1.0;
    unsigned int duration = doc["duration_s"] | 60;
    attackEndTime = millis() + (duration * 1000);
    Serial.printf("[ATTACK] FDI Activated: V_scale=%.2f, I_scale=%.2f, Duration=%ds\n", fdiVoltageScale, fdiCurrentScale, duration);
  } 
  else if (strcmp(cmd, "FREEZE") == 0) {
    attackFreezeActive = true;
    attackFdiActive = false;
    unsigned int duration = doc["duration_s"] | 30;
    freezeEndTime = millis() + (duration * 1000);
    Serial.printf("[ATTACK] FREEZE Activated for %ds\n", duration);
  }
  else if (strcmp(cmd, "STOP_ATTACK") == 0) {
    attackFdiActive = false;
    attackFreezeActive = false;
    Serial.println("[ATTACK] Stopped");
  }
}

// ==============================================================================
// SECTION 9 — Reconnection logic
// ==============================================================================
void ensureWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  
  Serial.print("Connecting to WiFi");
  // SECTION 2 — Static IP setup
  WiFi.config(staticIP, gateway, subnet, dns);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  int backoff = 1000;
  int attempt = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(backoff);
    Serial.print(".");
    backoff = min(backoff * 2, 30000);
    attempt++;
    if (attempt > 6) { // Reaches ~30s total
      Serial.println(" WiFi failed. Restarting.");
      ESP.restart();
    }
  }
  Serial.println("\nWiFi Connected. IP: " + WiFi.localIP().toString());
}

void ensureMQTT() {
  if (mqtt.connected()) return;
  
  int attempt = 0;
  while (!mqtt.connected()) {
    Serial.print("Connecting MQTT...");
    if (mqtt.connect(NODE_ID)) {
      Serial.println("OK");
      mqtt.subscribe(MQTT_TOPIC_SUB);
    } else {
      Serial.print("Failed, rc=");
      Serial.print(mqtt.state());
      Serial.println(". Retrying in 3s...");
      delay(3000);
      attempt++;
      if (attempt >= 5) {
        Serial.println("MQTT max retries reached. Restarting.");
        ESP.restart();
      }
    }
  }
}

// ==============================================================================
// Setup & Loop
// ==============================================================================
void setup() {
  // SECTION 10 — Serial Debug
  Serial.begin(115200);
  pzemSerial.begin(9600, SERIAL_8N1, 16, 17); // SECTION 3
  
  // SECTION 6
  mqtt.setServer(MQTT_SERVER, MQTT_PORT);
  mqtt.setCallback(mqttCallback);
  mqtt.setBufferSize(1024);

  ensureWiFi();
  
  // SECTION 8 — NTP
  timeClient.begin();
  timeClient.update();
}

void loop() {
  ensureWiFi();
  ensureMQTT();
  mqtt.loop();

  // Handle active attacks timeouts
  unsigned long currentMillis = millis();
  if (attackFdiActive && currentMillis > attackEndTime) {
    attackFdiActive = false;
    Serial.println("[ATTACK] FDI Expired");
  }
  if (attackFreezeActive && currentMillis > freezeEndTime) {
    attackFreezeActive = false;
    Serial.println("[ATTACK] FREEZE Expired");
  }

  if (currentMillis - lastPublishTime >= PUBLISH_INTERVAL_MS) {
    lastPublishTime = currentMillis;

    // 4. Read PZEM-004T
    PzemData data = readPzem();
    if (!data.valid) {
      Serial.println("[ERROR] PZEM Read Failed");
    }

    // 5. Apply attack modifications
    if (attackFreezeActive) {
      if (frozenVoltage == 0.0 && data.valid) {
        // Init freeze values
        frozenVoltage = data.voltage;
        frozenCurrent = data.current;
        frozenPower = data.power;
        frozenEnergy = data.energy;
        frozenFreq = data.frequency;
        frozenPf = data.pf;
      }
      if (frozenVoltage != 0.0) {
        data.voltage = frozenVoltage;
        data.current = frozenCurrent;
        data.power = frozenPower;
        data.energy = frozenEnergy;
        data.frequency = frozenFreq;
        data.pf = frozenPf;
        data.valid = true;
      }
    } else if (attackFdiActive && data.valid) {
      data.voltage *= fdiVoltageScale;
      data.current *= fdiCurrentScale;
      data.power = data.voltage * data.current * data.pf; // Recalculate power to match
    }

    // 6. Build JSON payload
    if (data.valid) {
      timeClient.update(); // 10. Check NTP
      
      StaticJsonDocument<512> doc;
      doc["alarm"] = data.alarm;
      doc["crc_errors"] = crcErrorCount;
      doc["current_A"] = round(data.current * 1000.0) / 1000.0;
      doc["energy_Wh"] = data.energy;
      doc["frequency_Hz"] = round(data.frequency * 10.0) / 10.0;
      doc["node_id"] = NODE_ID;
      doc["power_W"] = round(data.power * 10.0) / 10.0;
      doc["power_factor"] = round(data.pf * 100.0) / 100.0;
      doc["rssi_dBm"] = WiFi.RSSI();
      doc["seq"] = sequenceNumber++;
      doc["timestamp"] = timeClient.getEpochTime();
      doc["voltage_V"] = round(data.voltage * 10.0) / 10.0;

      String payloadString;
      serializeJson(doc, payloadString);

      // 7. Compute HMAC
      String hmac = computeHMAC(payloadString.c_str(), HMAC_SECRET_KEY);
      doc["hmac"] = hmac;

      String finalPayload;
      serializeJson(doc, finalPayload);

      // 8. Publish to MQTT
      mqtt.publish(MQTT_TOPIC_PUB, finalPayload.c_str(), false); 
      
      // 9. Print debug output
      Serial.printf("[%s][%02d:%02d:%02d] V=%.1f I=%.3f P=%.1f PF=%.2f | MQTT OK | HMAC=%s...\n",
        NODE_ID, timeClient.getHours(), timeClient.getMinutes(), timeClient.getSeconds(),
        data.voltage, data.current, data.power, data.pf, hmac.substring(0, 4).c_str());
        
      if (attackFdiActive) {
        Serial.printf("[ATTACK: FDI voltagex%.1f remaining %ds]\n", fdiVoltageScale, (attackEndTime - currentMillis) / 1000);
      } else if (attackFreezeActive) {
        Serial.printf("[ATTACK: FREEZE remaining %ds]\n", (freezeEndTime - currentMillis) / 1000);
      }
    }
  }
}
