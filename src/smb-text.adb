with SMB.Core_Text;

package body SMB.Text is
   pragma SPARK_Mode (Off);

   procedure Check (Status : SMB.Core_Status) is
   begin
      if Status /= SMB.Ok then
         raise SMB.Protocol_Error with
           "invalid SMB text encoding: " & SMB.Core_Status'Image (Status);
      end if;
   end Check;

   function To_UTF16LE (Value : String) return SMB.Bytes is
      Output : SMB.Bytes (1 .. Value'Length * 2);
      Used : Natural;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Text.UTF8_To_UTF16 (Value, Output, Used, Status);
      Check (Status);
      return Output (Output'First .. Output'First + Used - 1);
   end To_UTF16LE;

   function From_UTF16LE (Value : SMB.Bytes) return String is
      Output : String (1 .. Value'Length * 2);
      Used : Natural;
      Status : SMB.Core_Status;
   begin
      SMB.Core_Text.UTF16_To_UTF8 (Value, Output, Used, Status);
      Check (Status);
      return Output (Output'First .. Output'First + Used - 1);
   end From_UTF16LE;

   function NTLM_Username (Value : String) return String is
      Output : String (Value'Range);
      Status : SMB.Core_Status;
   begin
      SMB.Core_Text.Uppercase_NTLM_User (Value, Output, Status);
      if Status /= SMB.Ok then
         raise SMB.Authentication_Error with
           "NTLM usernames must be ASCII";
      end if;
      return Output;
   end NTLM_Username;
end SMB.Text;
