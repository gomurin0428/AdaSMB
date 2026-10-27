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

   function Is_Path_Separator (C : Character) return Boolean is
     (C = '/' or else C = '\');

   function Normalized_Path_Character (C : Character) return Character is
     (if C = '/' then '\' else C);

   function Valid_Path_Character
     (Input : String; Offset : Natural) return Boolean is
     (Input (Input'First + Offset) /= Character'Val (0)
      and then Input (Input'First + Offset) /= ':'
      and then
        (if Is_Path_Separator (Input (Input'First + Offset)) then
           Offset > 0 and then Offset < Input'Length - 1
           and then not Is_Path_Separator (Input (Input'First + Offset - 1)))
      and then not
        ((Offset = 0
          or else Is_Path_Separator (Input (Input'First + Offset - 1)))
         and then Input'Length - Offset >= 2
         and then Input (Input'First + Offset) = '.'
         and then Input (Input'First + Offset + 1) = '.'
         and then (Input'Length - Offset = 2
                   or else Is_Path_Separator (Input (Input'First + Offset + 2)))))
   with Pre => Input'Length <= 65_534 and then Offset < Input'Length;

   function Lexically_Valid_Path
     (Input : String; Allow_Empty : Boolean) return Boolean is
     (if Input'Length = 0 then Allow_Empty
      else (for all Offset in 0 .. Input'Length - 1 =>
        Valid_Path_Character (Input, Offset)))
   with Pre => Input'Length <= 65_534;

   procedure Validate_Path
     (Input : String;
      Output : out String;
      Allow_Empty : Boolean;
      Status : out SMB.Core_Status)
   with Pre => Input'Length <= 65_534
     and then Output'Length = Input'Length,
     Post =>
       (if Lexically_Valid_Path (Input, Allow_Empty) then
          Status = SMB.Ok
          and then
            (if Input'Length > 0 then
               (for all Offset in 0 .. Input'Length - 1 =>
                  Output (Output'First + Offset) =
                    Normalized_Path_Character (Input (Input'First + Offset))))
        else Status = SMB.Invalid_Value
          and then (for all C of Output => C = Character'Val (0)));

   function Lexically_Valid_Share (Input : String) return Boolean is
     (Input'Length > 0
      and then (for all C of Input =>
        C /= Character'Val (0) and then C /= ':'
        and then not Is_Path_Separator (C)))
   with Pre => Input'Length <= 255;

   procedure Validate_Share
     (Input : String;
      Status : out SMB.Core_Status)
   with Pre => Input'Length <= 255,
     Post => Status =
       (if Lexically_Valid_Share (Input) then SMB.Ok else SMB.Invalid_Value);
end SMB.Core_Text;
