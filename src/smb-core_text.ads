package SMB.Core_Text is
   pragma SPARK_Mode (On);

   procedure UTF8_To_UTF16
     (Input : String;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre =>
     Input'Length <= SMB.Maximum_Frame_Size
     and Output'Length <= 2 * SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure UTF16_To_UTF8
     (Input : SMB.Bytes;
      Output : out String;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre =>
     Input'Length <= SMB.Maximum_Frame_Size
     and Output'Length <= 2 * SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length;

   procedure Validate_UTF16
     (Input : SMB.Bytes;
      Status : out SMB.Core_Status)
   with Pre => Input'Length <= 65_534;

   procedure Uppercase_NTLM_User
     (Input : String;
      Output : out String;
      Status : out SMB.Core_Status)
   with Pre =>
     Input'Length <= SMB.Maximum_Frame_Size
     and Output'Length <= SMB.Maximum_Frame_Size;

   procedure Validate_Path
     (Input : String;
      Output : out String;
      Allow_Empty : Boolean;
      Status : out SMB.Core_Status)
   with Pre => Input'Length <= 65_534
     and then Output'Length = Input'Length,
     Post => Output'Length = Input'Length;

   procedure Validate_Share
     (Input : String;
      Status : out SMB.Core_Status)
   with Pre => Input'Length <= 255;
end SMB.Core_Text;
