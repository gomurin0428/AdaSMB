with SMB.Crypto;

package SMB.Core_Auth is
   pragma SPARK_Mode (On);

   Maximum_Credential_Bytes : constant := 4_096;
   Maximum_Security_Token : constant := 65_535;

   function Storage_Bounded
     (Data : SMB.Bytes; Limit : Natural) return Boolean is
     (Data'Last < Data'First
      or else Data'Last - Data'First < Limit);

   function Storage_Bounded
     (Data : String; Limit : Natural) return Boolean is
     (Data'Last < Data'First
      or else Data'Last - Data'First < Limit);

   procedure Build_Negotiate_Token
     (Output : in out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with
     Pre => Storage_Bounded (Output, Maximum_Security_Token),
     Post => Used <= Output'Length
       and then (if Status /= SMB.Ok then Used = 0);

   procedure Authenticate
     (User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Server_Token : SMB.Bytes;
      Current_Filetime : SMB.QWord;
      Output : in out SMB.Bytes;
      Used : out Natural;
      Session_Key : out SMB.Crypto.Digest_128;
      Status : out SMB.Core_Status)
   with
     Pre =>
       Storage_Bounded (User, Maximum_Credential_Bytes)
       and then Storage_Bounded (Password, Maximum_Credential_Bytes)
       and then Storage_Bounded (Domain, Maximum_Credential_Bytes)
       and then Storage_Bounded (Nonce, 8)
       and then Nonce'Length = 8
       and then Storage_Bounded (Server_Token, Maximum_Security_Token)
       and then Storage_Bounded (Output, Maximum_Security_Token),
     Post =>
       Used <= Output'Length
       and then
         (if Status /= SMB.Ok then
            Used = 0 and Session_Key = (Session_Key'Range => 0));
end SMB.Core_Auth;
