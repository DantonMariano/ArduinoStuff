/*
   ----------------------------------------------------------------------------
   This is a MFRC522 library example; see https://github.com/miguelbalboa/rfid
   for further details and other examples.

   NOTE: The library file MFRC522.h has a lot of useful info. Please read it.

   Released into the public domain.
   ----------------------------------------------------------------------------
   Example sketch/program which will try the most used default keys listed in
   https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys to dump the
   block 0 of a MIFARE RFID card using a RFID-RC522 reader.

   Typical pin layout used:
   -----------------------------------------------------------------------------------------
               MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
               Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
   Signal      Pin          Pin           Pin       Pin        Pin              Pin
   -----------------------------------------------------------------------------------------
   RST/Reset   RST          8             5         D9         RESET/ICSP-5     RST
   SPI SS      SDA(SS)      9             53        D10        10               10
   SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
   SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
   SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15

*/

#include <SPI.h>
#include <MFRC522.h>
#include <SPI.h>
#include <HttpClient.h>
#include <Ethernet.h>
#include <EthernetClient.h>
#include <Wire.h> 
#include <LiquidCrystal_I2C.h>


//DEFINES
#define mySerial Serial1
#define RST_PIN         8           // Configurable, see typical pin layout above
#define SS_PIN          53          // Configurable, see typical pin layout above
#define buzzer          7           // pino do buzzer
#define porta           31          // pino da relé
// INSTANCIAS
MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.
LiquidCrystal_I2C lcd(0x27,20,4);


// Number of known default keys (hard-coded)
// NOTE: Synchronize the NR_KNOWN_KEYS define with the defaultKeys[] array
#define NR_KNOWN_KEYS   8
// Known keys, see: https://code.google.com/p/mfcuk/wiki/MifareClassicDefaultKeys
byte knownKeys[NR_KNOWN_KEYS][MFRC522::MF_KEY_SIZE] =  {
  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF = factory default
  {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
  {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
  {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
  {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
  {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
  {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // 00 00 00 00 00 00
};


// Name of the server we want to connect to
//const char kHostname[] = "arduino.cc";
// Path to download (this is the bit after the hostname in the URL
// that you want to download
//const char kPath[] = "/";

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
String lastcpf = "";
String digitalTemplateString = "";
// Number of milliseconds to wait without receiving any data before we give up
const int kNetworkTimeout = 30*1000;
// Number of milliseconds to wait if no data is available before trying again
const int kNetworkDelay = 1000;


/*
   Initialize.
*/
void setup() {
  lcd.init();
  lcd.backlight();
  aproxime_lcd();
  Serial.begin(9600);         // Initialize serial communications with the PC
  while (!Serial);            // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();                // Init SPI bus
  mfrc522.PCD_Init();         // Init MFRC522 card
  Serial.println(F("APROXIME O SEU CARTAO DE IDENTIFICAÇAO."));
  while (Ethernet.begin(mac) != 1)
  {
    Serial.println("Erro ao adquirir endereço IP via DHCP, tentando novamente...");
    delay(15000);
  }
  digitalWrite(3, HIGH);
  //pinagem
  pinMode(3, OUTPUT);
  pinMode(buzzer, OUTPUT);
  pinMode(porta, OUTPUT);
  digitalWrite(porta,HIGH);
  // set the data rate for the sensor serial port
}


/*
   Helper routine to dump a byte array as hex values to Serial.
*/
String dump_byte_array(byte *buffer, byte bufferSize) {
  String cpfhex = "";
  char str[10];
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
    sprintf(str, "%X", buffer[i]);
    cpfhex+=str;
  }
  Serial.println();
  return cpfhex;
}


//(( String strcpf 
String teste;
String strcpf;
/*
   Try using the PICC (the tag/card) with the given key to access block 0.
   On success, it will show the key details, and dump the block data on Serial.

   @return true when the given key worked, false otherwise.
*/
bool try_key(MFRC522::MIFARE_Key *key)
{
  bool result = false;
  byte buffer[18];
  byte block = 4;
  MFRC522::StatusCode status;
  
  // Serial.println(F("Authenticating using key A..."));
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    // Serial.print(F("PCD_Authenticate() failed: "));
    // Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  // Read block
  byte byteCount = sizeof(buffer);
  status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
  if (status != MFRC522::STATUS_OK) {
    // Serial.print(F("MIFARE_Read() failed: "));
    // Serial.println(mfrc522.GetStatusCodeName(status));
  }
  else {
    // Successful read
    result = true;
    Serial.print(F("Success with key:"));
    dump_byte_array((*key).keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    // Dump block data
    Serial.print(F("Block ")); Serial.print(block); Serial.print(F(":"));
    strcpf = dump_byte_array(buffer, 5);
    Serial.println(strcpf);
  }
  Serial.println();

  mfrc522.PICC_HaltA();       // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
  return result;
}
// LCD functs
void aproxime_lcd(){
  lcd.setCursor(0,0);
  lcd.print("APROXIME O");
  lcd.setCursor(0,1);
  lcd.print("SEU CARTAO DE");
  lcd.setCursor(0,2);
  lcd.print("IDENTIFICAÇAO.");
  lcd.setCursor(0,3);
  lcd.print("--------------------");
}
void permitido_lcd(){
  lcd.clear();
  lcd.setCursor(0,0);
  lcd.print("--------------------");
  lcd.setCursor(0,1);
  lcd.print("ACESSO");
  lcd.setCursor(0,2);
  lcd.print("PERMITIDO.");
  lcd.setCursor(0,3);
  lcd.print("--------------------");
}
void negado_lcd(){
  lcd.clear();
  lcd.setCursor(0,0);
  lcd.print("--------------------");
  lcd.setCursor(0,1);
  lcd.print("ACESSO NAO");
  lcd.setCursor(0,2);
  lcd.print("AUTORIZADO.");
  lcd.setCursor(0,3);
  lcd.print("--------------------");
}
void naocad_lcd(){
  lcd.clear();
  lcd.setCursor(0,0);
  lcd.print("--------------------");
  lcd.setCursor(0,1);
  lcd.print("CARTAO NAO");
  lcd.setCursor(0,2);
  lcd.print("CADASTRADO.");
  lcd.setCursor(0,3);
  lcd.print("--------------------");
}
void aguarde_lcd(){
  lcd.clear();
  lcd.setCursor(0,0);
  lcd.print("--------------------");
  lcd.setCursor(0,1);
  lcd.print("POR FAVOR,");
  lcd.setCursor(0,2);
  lcd.print("AGUARDE...");
  lcd.setCursor(0,3);
  lcd.print("--------------------");
}
void aviso_dv_lcd(){
  lcd.clear();
  lcd.setCursor(0,0);
  lcd.print("--------------------");
  lcd.setCursor(0,1);
  lcd.print("AGUARDE ANTES");
  lcd.setCursor(0,2);
  lcd.print("DE REPETIR...");
  lcd.setCursor(0,3);
  lcd.print("--------------------");
}
void insira_digital_lcd(){
  lcd.clear();
  lcd.setCursor(0,0);
  lcd.print("INSIRA A SUA");
  lcd.setCursor(0,1);
  lcd.print("DIGITAL...");
}
void retire_digital_lcd(){
  lcd.clear();
  lcd.setCursor(0,0);
  lcd.print("RETIRE A SUA");
  lcd.setCursor(0,1);
  lcd.print("DIGITAL...");
}
// buzzers functs
void sem_acesso_buzz(){
  digitalWrite(buzzer,HIGH);
  delay(100);
  digitalWrite(buzzer,LOW);
  delay(50);
  digitalWrite(buzzer,HIGH);
  delay(100);
  digitalWrite(buzzer,LOW);
  delay(50);
  digitalWrite(buzzer,HIGH);
  delay(250);
  digitalWrite(buzzer,LOW);  
}

void aviso_buzz(){
  digitalWrite(buzzer,HIGH);
  delay(100);
  digitalWrite(buzzer,LOW);
  delay(50);
  digitalWrite(buzzer,HIGH);
  delay(250);
  digitalWrite(buzzer,LOW);  
}

void permitido_buzz(){
  digitalWrite(buzzer,HIGH);
  delay(250);
  digitalWrite(buzzer,LOW);
}

void lendo_buzz(){
  digitalWrite(buzzer,HIGH);
  delay(100);
  digitalWrite(buzzer,LOW);
}
// GPIO FUNCTS
void abrir_porta(){
  digitalWrite(porta,LOW);
  delay(3000);  
  digitalWrite(porta,HIGH);
}


/*
   Main loop.
*/
void loop() {
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  EthernetClient c;
  HttpClient http(c);
  HttpClient http2(c);
  int err = 0;
  //pinMode(10,OUTPUT);
  digitalWrite(10,HIGH);
  aproxime_lcd();
  delay(100);
  if ( ! mfrc522.PICC_IsNewCardPresent())
    return;

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial())
    return;

  // Show some details of the PICC (that is: the tag/card)
  Serial.print(F("Card UID:"));
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

  // Try the known default keys
  MFRC522::MIFARE_Key key;
  for (byte k = 0; k < NR_KNOWN_KEYS; k++) {
    aguarde_lcd();
    // Copy the known key into the MIFARE_Key structure
    for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
      key.keyByte[i] = knownKeys[k][i];
    }
    // Try the key
    if (try_key(&key)) {
      Serial.println("Key Worked!");
      lendo_buzz();
      Serial.println(strcpf);
      if ( strcpf == lastcpf ) {
        Serial.println("AGUARDE ANTES DE PASSAR O MESMO CARTAO.");
        aviso_dv_lcd();
        lastcpf = "";
        aviso_buzz();
        delay(2000);
        return;
      }
      lastcpf = strcpf;
      //digitalWrite(10, HIGH);
      char getcpf[23] = "/acesso/cpf/0000000000";
      char kHostname[] = "portal.polyterminais.com.br"; //portal.polyterminais.com.br:8090/acesso/{cpf_hex}
      for(int i=0; i<10;i++){
        getcpf[12+i] = strcpf[i];
      }
      Serial.println(getcpf);
      int req = 0;
      err = http.get(kHostname,8090,getcpf);
      if (err == 0) {
        err = http.responseStatusCode();
        Serial.println(err);
        if (err == 200){
          Serial.println(c.remoteIP());
          Serial.println("ACESSO PERMITIDO");
          insira_digital_lcd();
          lendo_buzz();
          lastcpf = "";
          permitido_lcd();
          permitido_buzz();
          abrir_porta();
        } else if (err == 404) {
          Serial.println("USUARIO NAO CADASTRADO");
          naocad_lcd();
          sem_acesso_buzz();
        } else {
          Serial.println("ACESSO NAO PERMITIDO");
          negado_lcd();
          sem_acesso_buzz();  
        }
        http.stop();
      } else {
        Serial.println(err);
        Serial.println("COMUNICAÇAO FALHOU MUITAS TENTATIVAS FORAM FEITAS, REINICIANDO ARDUINO");
        aviso_buzz();
        http.stop();
        delay(200);
        digitalWrite(3, LOW);
      }
      //digitalWrite(10, LOW);
      delay(2000);
      break;
    }

    // http://arduino.stackexchange.com/a/14316
    if ( ! mfrc522.PICC_IsNewCardPresent())
      break;
    if ( ! mfrc522.PICC_ReadCardSerial())
      break;
  }
}

/*  
 *  SENSOR DIGITAL
 *  FUNCTS 
*/
