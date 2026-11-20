with SMB.Spec.Unicode;

package SMB.Core_Text is
   pragma SPARK_Mode (On);
   use type SMB.Byte;

   function UTF16_Unit (Input : SMB.Bytes; Index : Natural) return Natural is
     (Natural (Input (Input'First + 2 * Index))
      + 256 * Natural (Input (Input'First + 2 * Index + 1)))
   with Ghost,
     Annotate => (GNATprove, Inline_For_Proof),
     Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
       and then Index < Input'Length / 2;

   function Valid_UTF16_Unit
     (Input : SMB.Bytes; Index : Natural) return Boolean is
     (UTF16_Unit (Input, Index) /= 0
      and then
        (if UTF16_Unit (Input, Index) in 16#D800# .. 16#DBFF# then
           Index + 1 < Input'Length / 2
           and then UTF16_Unit (Input, Index + 1) in 16#DC00# .. 16#DFFF#)
      and then
        (if UTF16_Unit (Input, Index) in 16#DC00# .. 16#DFFF# then
           Index > 0
           and then UTF16_Unit (Input, Index - 1) in 16#D800# .. 16#DBFF#))
   with Ghost,
     Annotate => (GNATprove, Inline_For_Proof),
     Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size
       and then Index < Input'Length / 2;

   function Valid_UTF16_Text (Input : SMB.Bytes) return Boolean is
     (Input'Length mod 2 = 0
      and then
        (if Input'Length > 0 then
           (for all Index in 0 .. Input'Length / 2 - 1 =>
              Valid_UTF16_Unit (Input, Index))))
   with Ghost, Pre => Input'Length <= 2 * SMB.Maximum_Frame_Size;

   procedure Validate_UTF16
     (Input : SMB.Bytes;
      Status : out SMB.Core_Status)
   with Pre => Input'Length <= 65_534,
     Post => Status =
       (if Input'Length mod 2 /= 0 then SMB.Invalid_Length
        elsif Valid_UTF16_Text (Input) then SMB.Ok
        else SMB.Invalid_Encoding);

   function ASCII_Only (Input : String) return Boolean is
     (for all C of Input => Character'Pos (C) <= 16#7F#)
   with Ghost;

   function NTLM_Uppercase_Character (C : Character) return Character is
     (if C in 'a' .. 'z' then Character'Val (Character'Pos (C) - 32) else C)
   with Ghost;

   procedure Uppercase_NTLM_User
     (Input : String;
      Output : out String;
      Status : out SMB.Core_Status)
   with Pre =>
     Input'Length <= SMB.Maximum_Frame_Size
     and Output'Length <= SMB.Maximum_Frame_Size,
     Post => Status =
       (if Output'Length /= Input'Length then SMB.Invalid_Length
        elsif ASCII_Only (Input) then SMB.Ok
        else SMB.Invalid_Encoding)
       and then
         (if Status = SMB.Ok and then Input'Length > 0 then
            (for all Offset in 0 .. Input'Length - 1 =>
               Output (Output'First + Offset) =
                 NTLM_Uppercase_Character (Input (Input'First + Offset))))
       and then
         (if Status = SMB.Invalid_Length then
            (for all C of Output => C = Character'Val (0)));

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
   --  The converters' postconditions state the whole output against
   --  SMB.Spec.Unicode, whose functions recurse once per scalar: checked
   --  at run time on inputs up to 1 MiB they would overflow the stack.
   --  They are proved and not checked at run time, even where every other
   --  contract is (assertion levels, which could mark just those clauses,
   --  need GNAT 16); test_suite checks them on every short input instead.
   --  This pragma applies to the end of the package.
   pragma Assertion_Policy (Post => Ignore);

   procedure UTF8_To_UTF16
     (Input : String;
      Output : out SMB.Bytes;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre =>
     Input'Length <= SMB.Maximum_Frame_Size
     and Output'Length <= 2 * SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length and then Used <= 2 * Input'Length
       and then Used mod 2 = 0
       and then
         (if Used > 0 then
            Valid_UTF16_Text
              (Output (Output'First .. Output'First + (Used - 1))))
       and then (if Status = SMB.Ok then (Used = 0) = (Input'Length = 0))
       and then (if Input'Length = 0 then Status = SMB.Ok)
       and then (if Output'Length >= 2 * Input'Length then
          Status in SMB.Ok | SMB.Invalid_Encoding)
       and then (for all Index in Output'Range =>
          (if Index - Output'First >= Used then Output (Index) = 0))
       --  Against SMB.Spec.Unicode: the first failure of a scan from the
       --  front, a sequence that does not fit before one that is refused;
       --  on success Input in UTF-16, on failure nothing.
       and then Status =
         (if SMB.Spec.Unicode.UTF16_Run_Size (Input, 0) > Output'Length
          then SMB.Invalid_Length
          elsif not SMB.Spec.Unicode.Is_Client_UTF8 (Input)
          then SMB.Invalid_Encoding
          else SMB.Ok)
       and then
         (if Status = SMB.Ok then
            Used = SMB.Spec.Unicode.UTF16_Run_Size (Input, 0)
            and then SMB.Spec.Unicode.Is_UTF16_Run
              (Input, 0, Output (Output'First .. Output'First + (Used - 1)),
               0)
          else Used = 0);


   procedure UTF16_To_UTF8
     (Input : SMB.Bytes;
      Output : out String;
      Used : out Natural;
      Status : out SMB.Core_Status)
   with Pre =>
     Input'Length <= SMB.Maximum_Frame_Size
     and Output'Length <= 2 * SMB.Maximum_Frame_Size,
     Post => Used <= Output'Length and then Used <= 2 * Input'Length
       and then (if Status = SMB.Ok then Input'Length mod 2 = 0
         and then Valid_UTF16_Text (Input)
         and then (Used = 0) = (Input'Length = 0))
       and then
         (if Input'Length mod 2 /= 0 then Status = SMB.Invalid_Length
          elsif Output'Length >= 2 * Input'Length then
             Status =
               (if Valid_UTF16_Text (Input) then SMB.Ok
                else SMB.Invalid_Encoding))
       and then (for all Index in Output'Range =>
          (if Index - Output'First >= Used then Output (Index) = Character'Val (0)))
       --  Against SMB.Spec.Unicode, as UTF8_To_UTF16: an odd length first,
       --  then the first failure of a scan from the front; on success Input
       --  in UTF-8, on failure nothing.
       and then Status =
         (if Input'Length mod 2 /= 0 then SMB.Invalid_Length
          elsif SMB.Spec.Unicode.UTF8_Run_Size (Input, 0) > Output'Length
          then SMB.Invalid_Length
          elsif not SMB.Spec.Unicode.Is_Client_UTF16 (Input)
          then SMB.Invalid_Encoding
          else SMB.Ok)
       and then
         (if Status = SMB.Ok then
            Used = SMB.Spec.Unicode.UTF8_Run_Size (Input, 0)
            and then SMB.Spec.Unicode.Is_UTF8_Run
              (Input, 0, Output (Output'First .. Output'First + (Used - 1)),
               0)
          else Used = 0);

end SMB.Core_Text;
