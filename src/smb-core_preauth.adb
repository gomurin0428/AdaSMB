package body SMB.Core_Preauth is
   pragma SPARK_Mode (On);

   procedure Update (Value : in out Hash_Value; Message : SMB.Bytes) is
      Context : SMB.Crypto.SHA512_Context;
   begin
      SMB.Crypto.SHA512_Start (Context);
      SMB.Crypto.SHA512_Update (Context, Value);
      SMB.Crypto.SHA512_Update (Context, Message);
      SMB.Crypto.SHA512_Finish (Context, Value);
   end Update;

end SMB.Core_Preauth;
