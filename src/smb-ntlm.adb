with SMB.Core_Auth;
with SMB.Crypto;

package body SMB.NTLM is
   function Negotiate_Token return SMB.Bytes is
      Buffer : SMB.Bytes
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
      Used : Natural := 0;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Auth.Build_Negotiate_Token (Buffer, Used, Status);
      if Status /= SMB.Ok or else Used = 0 then
         raise SMB.Authentication_Error with
           "SPNEGO negotiate token could not be constructed";
      end if;
      return Buffer (0 .. Used - 1);
   end Negotiate_Token;

   function Authenticate
     (User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Server_Token : SMB.Bytes;
      Current_Filetime : SMB.QWord := 0) return Authentication_Result
   is
      Buffer : SMB.Bytes
        (0 .. SMB.Core_Auth.Maximum_Security_Token - 1) := (others => 0);
      Used : Natural := 0;
      Key : SMB.Crypto.Digest_128 := (others => 0);
      Status : SMB.Core_Status;
   begin
      if User'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Password'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Domain'Length > SMB.Core_Auth.Maximum_Credential_Bytes
        or else Nonce'Length /= 8
      then
         raise SMB.Authentication_Error with
           "NTLM credentials or nonce exceed supported bounds";
      end if;
      if Server_Token'Length > SMB.Core_Auth.Maximum_Security_Token then
         raise SMB.Authentication_Error with
           "SPNEGO token exceeds supported authentication resources";
      end if;
      SMB.Core_Auth.Authenticate
        (User, Password, Domain, Nonce, Server_Token,
         Current_Filetime, Buffer, Used, Key, Status);
      if Status /= SMB.Ok or else Used = 0 then
         if Status = SMB.Resource_Limit
           or else Status = SMB.Unsupported_Feature
         then
            raise SMB.Authentication_Error with
              "NTLM credentials or authentication resources are unsupported";
         else
            raise SMB.Protocol_Error with
              "server returned a malformed or unsupported NTLM challenge";
         end if;
      end if;
      return
        (Token_Last => Used - 1,
         Key_Last => Key'Length - 1,
         Security_Token => Buffer (0 .. Used - 1),
         Session_Key => Key);
   end Authenticate;
end SMB.NTLM;
