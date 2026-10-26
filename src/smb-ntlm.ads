package SMB.NTLM is
   type Authentication_Result
     (Token_Last : Natural; Key_Last : Natural) is record
      Security_Token : SMB.Bytes (0 .. Token_Last);
      Session_Key    : SMB.Bytes (0 .. Key_Last);
   end record;

   function Negotiate_Token return SMB.Bytes;
   function Authenticate
     (User, Password, Domain : String;
      Nonce : SMB.Bytes;
      Server_Token : SMB.Bytes;
      Current_Filetime : SMB.QWord := 0) return Authentication_Result;
end SMB.NTLM;
