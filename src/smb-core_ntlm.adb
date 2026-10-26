package body SMB.Core_NTLM is
   pragma SPARK_Mode (On);

   use type SMB.Byte;

   function Mechanism_List_MIC
     (Session_Key : SMB.Crypto.Digest_128;
      From_Server : Boolean) return SMB.Crypto.Digest_128
   is
      Magic : constant String :=
        (if From_Server then
           "session key to server-to-client signing key magic constant"
         else "session key to client-to-server signing key magic constant")
        & Character'Val (0);
      Material : SMB.Bytes (0 .. 15 + Magic'Length) := (others => 0);
      Message : constant SMB.Bytes :=
        (0, 0, 0, 0, 16#30#, 16#0C#, 16#06#, 16#0A#,
         16#2B#, 16#06#, 16#01#, 16#04#, 16#01#,
         16#82#, 16#37#, 16#02#, 16#02#, 16#0A#);
      Result : SMB.Crypto.Digest_128 := (others => 0);
   begin
      Material (0 .. 15) := Session_Key;
      for I in Magic'Range loop
         Material (16 + I - Magic'First) := SMB.Byte (Character'Pos (Magic (I)));
      end loop;
      declare
         Key : constant SMB.Crypto.Digest_128 := SMB.Crypto.MD5 (Material);
         Hash : constant SMB.Crypto.Digest_128 := SMB.Crypto.HMAC_MD5 (Key, Message);
      begin
         Result (0) := 1;
         Result (4 .. 11) := Hash (0 .. 7);
         return Result;
      end;
   end Mechanism_List_MIC;

   procedure Read_TLV
     (Data : SMB.Bytes;
      Position : in out Natural;
      Tag : out SMB.Byte;
      Content_Offset : out Natural;
      Content_Length : out Natural;
      Status : out SMB.Core_Status)
     with Pre => Data'Length <= SMB.Maximum_Frame_Size
       and then Position <= Data'Length,
       Post => Position <= Data'Length
         and then Content_Offset <= Data'Length
         and then Content_Length <= Data'Length - Content_Offset
         and then (if Status = SMB.Ok then
           Position = Content_Offset + Content_Length
           and then Position > Position'Old);

   procedure Read_TLV
     (Data : SMB.Bytes;
      Position : in out Natural;
      Tag : out SMB.Byte;
      Content_Offset : out Natural;
      Content_Length : out Natural;
      Status : out SMB.Core_Status)
   is
      First_Length : Natural;
      Length_Bytes : Natural;
      Value : Natural := 0;
   begin
      Tag := 0;
      Content_Offset := 0;
      Content_Length := 0;
      if Position >= Data'Length then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Tag := Data (Data'First + Position);
      Position := Position + 1;
      if Position >= Data'Length then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      First_Length := Natural (Data (Data'First + Position));
      Position := Position + 1;
      if First_Length < 128 then
         Value := First_Length;
      else
         Length_Bytes := First_Length - 128;
         if Length_Bytes = 0 or else Length_Bytes > 3
           or else Length_Bytes > Data'Length - Position
           or else Data (Data'First + Position) = 0
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         for Index in 1 .. Length_Bytes loop
            pragma Loop_Invariant (Position >= Position'Loop_Entry);
            pragma Loop_Invariant
              (Position <= Data'Length - (Length_Bytes - Index + 1));
            if Value > (SMB.Maximum_Frame_Size - 255) / 256 then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            Value :=
              Value * 256
              + Natural (Data (Data'First + Position));
            Position := Position + 1;
         end loop;
         if Value < 128
           or else (Length_Bytes = 2 and then Value < 256)
           or else (Length_Bytes = 3 and then Value < 65_536)
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
      end if;
      if Value > Data'Length - Position then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Content_Offset := Position;
      Content_Length := Value;
      Position := Position + Value;
      Status := SMB.Ok;
   end Read_TLV;

   function Is_NTLM_OID
     (Data : SMB.Bytes; Offset, Length : Natural) return Boolean
     with Pre => Data'Length <= SMB.Maximum_Frame_Size;

   function Is_NTLM_OID
     (Data : SMB.Bytes; Offset, Length : Natural) return Boolean
   is
      OID : constant SMB.Bytes :=
        (16#2B#, 16#06#, 16#01#, 16#04#, 16#01#,
         16#82#, 16#37#, 16#02#, 16#02#, 16#0A#);
   begin
      if Length /= OID'Length
        or else Offset > Data'Length
        or else Length > Data'Length - Offset
      then
         return False;
      end if;
      for Index in OID'Range loop
         if Data (Data'First + Offset + Index - OID'First) /= OID (Index) then
            return False;
         end if;
      end loop;
      return True;
   end Is_NTLM_OID;

   procedure Extract_Challenge
     (Token : SMB.Bytes;
      Type2_Offset : out Natural;
      Type2_Length : out Natural;
      Status : out SMB.Core_Status)
   is
      Position : Natural := 0;
      Tag : SMB.Byte;
      Outer_Offset : Natural;
      Outer_Length : Natural;
      Response_Offset : Natural;
      Response_Length : Natural;
      Sequence_Offset : Natural;
      Sequence_Length : Natural;
      Sequence_End : Natural;
      Field_Offset : Natural;
      Field_Length : Natural;
      Field_End : Natural;
      Inner_Position : Natural;
      Inner_Tag : SMB.Byte;
      Inner_Offset : Natural;
      Inner_Length : Natural;
      Previous_Tag : Natural := 0;
      State_Seen : Boolean := False;
      Mechanism_Seen : Boolean := False;
      Response_Seen : Boolean := False;
      Parse_Status : SMB.Core_Status;
      SPNEGO_OID : constant SMB.Bytes :=
        (16#2B#, 16#06#, 16#01#, 16#05#, 16#05#, 16#02#);
   begin
      Type2_Offset := 0;
      Type2_Length := 0;
      if Token'Length = 0 then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Read_TLV
        (Token, Position, Tag, Outer_Offset, Outer_Length, Parse_Status);
      if Parse_Status /= SMB.Ok then
         Status := Parse_Status;
         return;
      end if;
      if Tag = 16#60# then
         if Position /= Token'Length then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Position := Outer_Offset;
         Read_TLV
           (Token, Position, Inner_Tag, Inner_Offset, Inner_Length, Parse_Status);
         if Parse_Status /= SMB.Ok
           or else Inner_Tag /= 16#06#
           or else Inner_Length /= SPNEGO_OID'Length
           or else Position > Outer_Offset + Outer_Length
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         for Index in SPNEGO_OID'Range loop
            if Token (Token'First + Inner_Offset + Index) /=
              SPNEGO_OID (Index)
            then
               Status := SMB.Invalid_Protocol;
               return;
            end if;
         end loop;
         Read_TLV
           (Token, Position, Tag, Response_Offset, Response_Length, Parse_Status);
         if Parse_Status /= SMB.Ok
           or else Tag /= 16#A1#
           or else Position /= Outer_Offset + Outer_Length
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
      elsif Tag = 16#A1# and then Position = Token'Length then
         Response_Offset := Outer_Offset;
         Response_Length := Outer_Length;
      else
         Status := SMB.Invalid_Encoding;
         return;
      end if;

      Position := Response_Offset;
      Read_TLV
        (Token, Position, Tag, Sequence_Offset, Sequence_Length, Parse_Status);
      if Parse_Status /= SMB.Ok
        or else Tag /= 16#30#
        or else Position /= Response_Offset + Response_Length
      then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Sequence_End := Sequence_Offset + Sequence_Length;
      Position := Sequence_Offset;
      while Position < Sequence_End loop
         pragma Loop_Invariant (Position <= Sequence_End);
         pragma Loop_Invariant (Type2_Offset <= Token'Length);
         pragma Loop_Invariant
           (Type2_Length <= Token'Length - Type2_Offset);
         pragma Loop_Invariant
           (not Response_Seen or else Type2_Length >= 48);
         pragma Loop_Variant (Increases => Position);
         Read_TLV
           (Token, Position, Tag, Field_Offset, Field_Length, Parse_Status);
         if Parse_Status /= SMB.Ok
           or else Position > Sequence_End
           or else Tag not in 16#A0# .. 16#A3#
           or else Natural (Tag) <= Previous_Tag
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Previous_Tag := Natural (Tag);
         Field_End := Field_Offset + Field_Length;
         Inner_Position := Field_Offset;
         if Tag = 16#A0# then
            Read_TLV
              (Token, Inner_Position, Inner_Tag,
               Inner_Offset, Inner_Length, Parse_Status);
            if Parse_Status /= SMB.Ok
              or else Inner_Tag /= 16#0A#
              or else Inner_Length /= 1
              or else Inner_Position /= Field_End
              or else State_Seen
              or else Token (Token'First + Inner_Offset) not in 1 | 3
            then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            State_Seen := True;
         elsif Tag = 16#A1# then
            Read_TLV
              (Token, Inner_Position, Inner_Tag,
               Inner_Offset, Inner_Length, Parse_Status);
            if Parse_Status /= SMB.Ok
              or else Inner_Tag /= 16#06#
              or else Inner_Position /= Field_End
              or else Mechanism_Seen
            then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if not Is_NTLM_OID (Token, Inner_Offset, Inner_Length) then
               Status := SMB.Invalid_Protocol;
               return;
            end if;
            Mechanism_Seen := True;
         elsif Tag = 16#A2# then
            Read_TLV
              (Token, Inner_Position, Inner_Tag,
               Inner_Offset, Inner_Length, Parse_Status);
            if Parse_Status /= SMB.Ok
              or else Inner_Tag /= 16#04#
              or else Inner_Position /= Field_End
              or else Response_Seen
              or else Inner_Length < 48
            then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if Token (Token'First + Inner_Offset) /= 16#4E#
              or else Token (Token'First + Inner_Offset + 1) /= 16#54#
              or else Token (Token'First + Inner_Offset + 2) /= 16#4C#
              or else Token (Token'First + Inner_Offset + 3) /= 16#4D#
              or else Token (Token'First + Inner_Offset + 4) /= 16#53#
              or else Token (Token'First + Inner_Offset + 5) /= 16#53#
              or else Token (Token'First + Inner_Offset + 6) /= 16#50#
              or else Token (Token'First + Inner_Offset + 7) /= 0
              or else Token (Token'First + Inner_Offset + 8) /= 2
              or else Token (Token'First + Inner_Offset + 9) /= 0
              or else Token (Token'First + Inner_Offset + 10) /= 0
              or else Token (Token'First + Inner_Offset + 11) /= 0
            then
               Status := SMB.Invalid_Protocol;
               return;
            end if;
            if not State_Seen or else not Mechanism_Seen then
               Status := SMB.Invalid_Protocol;
               return;
            end if;
            Type2_Offset := Inner_Offset;
            Type2_Length := Inner_Length;
            Response_Seen := True;
         else
            Status := SMB.Invalid_Protocol;
            return;
         end if;
      end loop;
      if Position /= Sequence_End
        or else not State_Seen
        or else not Mechanism_Seen
        or else not Response_Seen
      then
         Type2_Offset := 0;
         Type2_Length := 0;
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Status := SMB.Ok;
   end Extract_Challenge;

   procedure Validate_Final_Token
     (Token : SMB.Bytes;
      Status : out SMB.Core_Status;
      Expected_MIC : SMB.Bytes := (1 .. 0 => 0))
   is
      Position : Natural := 0;
      Tag : SMB.Byte;
      Outer_Offset : Natural;
      Outer_Length : Natural;
      Sequence_Offset : Natural;
      Sequence_Length : Natural;
      State_Seen : Boolean := False;
      MIC_Seen : Boolean := False;
      Previous_Tag : Natural := 0;
      Field_Offset : Natural;
      Field_Length : Natural;
      Inner_Position : Natural;
      Inner_Tag : SMB.Byte;
      Inner_Offset : Natural;
      Inner_Length : Natural;
      Parse_Status : SMB.Core_Status;
   begin
      if Token'Length = 0 then
         Status := (if Expected_MIC'Length = 0 then SMB.Ok else SMB.Signature_Error);
         return;
      end if;
      Read_TLV
        (Token, Position, Tag, Outer_Offset, Outer_Length, Parse_Status);
      if Parse_Status /= SMB.Ok
        or else Tag /= 16#A1#
        or else Position /= Token'Length
      then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Position := Outer_Offset;
      Read_TLV
        (Token, Position, Tag, Sequence_Offset, Sequence_Length, Parse_Status);
      if Parse_Status /= SMB.Ok
        or else Tag /= 16#30#
        or else Position /= Outer_Offset + Outer_Length
      then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      Position := Sequence_Offset;
      while Position < Sequence_Offset + Sequence_Length loop
         pragma Loop_Invariant
           (Position <= Sequence_Offset + Sequence_Length);
         pragma Loop_Variant (Increases => Position);
         Read_TLV
           (Token, Position, Tag, Field_Offset, Field_Length, Parse_Status);
         if Parse_Status /= SMB.Ok
           or else Position > Sequence_Offset + Sequence_Length
           or else Tag not in 16#A0# .. 16#A3#
           or else Natural (Tag) <= Previous_Tag
         then
            Status := SMB.Invalid_Encoding;
            return;
         end if;
         Previous_Tag := Natural (Tag);
         Inner_Position := Field_Offset;
         if Tag = 16#A0# then
            Read_TLV
              (Token, Inner_Position, Inner_Tag,
               Inner_Offset, Inner_Length, Parse_Status);
            if Parse_Status /= SMB.Ok
              or else Inner_Tag /= 16#0A#
              or else Inner_Length /= 1
              or else Inner_Position /= Field_Offset + Field_Length
              or else Token (Token'First + Inner_Offset) /= 0
            then
               Status := SMB.Unsupported_Feature;
               return;
            end if;
            State_Seen := True;
         elsif Tag = 16#A1# then
            Read_TLV
              (Token, Inner_Position, Inner_Tag,
               Inner_Offset, Inner_Length, Parse_Status);
            if Parse_Status /= SMB.Ok
              or else Inner_Tag /= 16#06#
              or else Inner_Position /= Field_Offset + Field_Length
              or else not Is_NTLM_OID (Token, Inner_Offset, Inner_Length)
            then
               Status := SMB.Unsupported_Feature;
               return;
            end if;
         elsif Tag = 16#A2# then
            Read_TLV
              (Token, Inner_Position, Inner_Tag,
               Inner_Offset, Inner_Length, Parse_Status);
            if Parse_Status /= SMB.Ok
              or else Inner_Tag /= 16#04#
              or else Inner_Length /= 0
              or else Inner_Offset /= Field_Offset + Field_Length
              or else Inner_Position /= Field_Offset + Field_Length
            then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
         elsif Tag = 16#A3# then
            Read_TLV
              (Token, Inner_Position, Inner_Tag,
               Inner_Offset, Inner_Length, Parse_Status);
            if Parse_Status /= SMB.Ok
              or else Inner_Tag /= 16#04#
              or else Inner_Length /= 16
              or else Expected_MIC'Length /= 16
              or else Inner_Position /= Field_Offset + Field_Length
            then
               Status := SMB.Invalid_Encoding;
               return;
            end if;
            if not SMB.Crypto.Constant_Time_Equal
              (Token (Token'First + Inner_Offset ..
                        Token'First + Inner_Offset + (Inner_Length - 1)),
               Expected_MIC)
            then
               Status := SMB.Signature_Error;
               return;
            end if;
            MIC_Seen := True;
         else
            Status := SMB.Unsupported_Feature;
            return;
         end if;
      end loop;
      if Position /= Sequence_Offset + Sequence_Length or else not State_Seen then
         Status := SMB.Invalid_Encoding;
         return;
      end if;
      if Expected_MIC'Length /= 0 and then not MIC_Seen then
         Status := SMB.Signature_Error;
         return;
      end if;
      Status := SMB.Ok;
   end Validate_Final_Token;
end SMB.Core_NTLM;
