--  The Unicode encoding forms the client converts between (The Unicode
--  Standard, Version 16.0, section 3.9 "Unicode Encoding Forms"): UTF-8,
--  the form of the caller's strings, whose Characters are its bytes, and
--  UTF-16, the form of the protocol's (MS-SMB2 2.2: "all textual strings
--  MUST be in Unicode ... using the 16-bit Unicode Transformation Format
--  (UTF-16)"), little-endian as every SMB2 field (SMB.Spec.Encoding).
--
--  A whole string is specified from the front: what a sequence at Position
--  is, then the rest from the position after it. Positions count from the
--  string's first index.
package SMB.Spec.Unicode
  with Ghost, SPARK_Mode
is
   use type SMB.Byte;

   --  D76: a Unicode scalar value is "Any Unicode code point except
   --  high-surrogate and low-surrogate code points": 0 to D7FF and E000 to
   --  10FFFF.
   function Is_Scalar (Value : Natural) return Boolean is
     (Value <= 16#10FFFF# and then Value not in 16#D800# .. 16#DFFF#);

   --  The scalars this client converts: every one but U+0000, which no
   --  name, share or credential it sends may hold (ours).
   function Is_Client_Scalar (Value : Natural) return Boolean is
     (Is_Scalar (Value) and then Value /= 0);

   function Byte_At (Text : String; Position : Natural) return Natural is
     (Character'Pos (Text (Text'First + Position)))
   with Pre => Position < Text'Length;

   --  Whether the byte at Position exists and lies in Low .. High.
   function Byte_In
     (Text : String; Position : Natural; Low, High : Natural) return Boolean
   is
     (Position < Text'Length
      and then Byte_At (Text, Position) in Low .. High);

   --  D92 and Table 3-7 (Well-Formed UTF-8 Byte Sequences): the length of
   --  the well-formed UTF-8 byte sequence that starts at Position, or 0 when
   --  none does. Its rows:
   --    U+0000..U+007F      00..7F
   --    U+0080..U+07FF      C2..DF  80..BF
   --    U+0800..U+0FFF      E0      A0..BF  80..BF
   --    U+1000..U+CFFF      E1..EC  80..BF  80..BF
   --    U+D000..U+D7FF      ED      80..9F  80..BF
   --    U+E000..U+FFFF      EE..EF  80..BF  80..BF
   --    U+10000..U+3FFFF    F0      90..BF  80..BF  80..BF
   --    U+40000..U+FFFFF    F1..F3  80..BF  80..BF  80..BF
   --    U+100000..U+10FFFF  F4      80..8F  80..BF  80..BF
   function UTF8_Length (Text : String; Position : Natural) return Natural is
     (case Byte_At (Text, Position) is
         when 16#00# .. 16#7F# => 1,
         when 16#C2# .. 16#DF# =>
           (if Byte_In (Text, Position + 1, 16#80#, 16#BF#) then 2 else 0),
         when 16#E0# =>
           (if Byte_In (Text, Position + 1, 16#A0#, 16#BF#)
              and then Byte_In (Text, Position + 2, 16#80#, 16#BF#)
            then 3 else 0),
         when 16#E1# .. 16#EC# | 16#EE# .. 16#EF# =>
           (if Byte_In (Text, Position + 1, 16#80#, 16#BF#)
              and then Byte_In (Text, Position + 2, 16#80#, 16#BF#)
            then 3 else 0),
         when 16#ED# =>
           (if Byte_In (Text, Position + 1, 16#80#, 16#9F#)
              and then Byte_In (Text, Position + 2, 16#80#, 16#BF#)
            then 3 else 0),
         when 16#F0# =>
           (if Byte_In (Text, Position + 1, 16#90#, 16#BF#)
              and then Byte_In (Text, Position + 2, 16#80#, 16#BF#)
              and then Byte_In (Text, Position + 3, 16#80#, 16#BF#)
            then 4 else 0),
         when 16#F1# .. 16#F3# =>
           (if Byte_In (Text, Position + 1, 16#80#, 16#BF#)
              and then Byte_In (Text, Position + 2, 16#80#, 16#BF#)
              and then Byte_In (Text, Position + 3, 16#80#, 16#BF#)
            then 4 else 0),
         when 16#F4# =>
           (if Byte_In (Text, Position + 1, 16#80#, 16#8F#)
              and then Byte_In (Text, Position + 2, 16#80#, 16#BF#)
              and then Byte_In (Text, Position + 3, 16#80#, 16#BF#)
            then 4 else 0),
         when others => 0)
   with Pre =>
     Text'Length <= SMB.Maximum_Frame_Size and then Position < Text'Length,
     Post =>
       UTF8_Length'Result <= 4
       and then UTF8_Length'Result <= Text'Length - Position;

   --  Table 3-6 (UTF-8 Bit Distribution): the scalar a well-formed sequence
   --  encodes. The first byte is 0xxxxxxx, 110yyyyy, 1110zzzz or
   --  11110uuu, and each later one 10xxxxxx; the scalar is their bits
   --  together.
   function UTF8_Scalar (Text : String; Position : Natural) return Natural is
     (case UTF8_Length (Text, Position) is
         when 1 => Byte_At (Text, Position),
         when 2 =>
           (Byte_At (Text, Position) - 16#C0#) * 64
           + (Byte_At (Text, Position + 1) - 16#80#),
         when 3 =>
           (Byte_At (Text, Position) - 16#E0#) * 4_096
           + (Byte_At (Text, Position + 1) - 16#80#) * 64
           + (Byte_At (Text, Position + 2) - 16#80#),
         when others =>
           (Byte_At (Text, Position) - 16#F0#) * 262_144
           + (Byte_At (Text, Position + 1) - 16#80#) * 4_096
           + (Byte_At (Text, Position + 2) - 16#80#) * 64
           + (Byte_At (Text, Position + 3) - 16#80#))
   with Pre =>
     Text'Length <= SMB.Maximum_Frame_Size
     and then Position < Text'Length
     and then UTF8_Length (Text, Position) > 0,
     Post => Is_Scalar (UTF8_Scalar'Result);

   --  Whether a sequence of a scalar this client converts starts at
   --  Position.
   function Valid_UTF8_At (Text : String; Position : Natural) return Boolean
   is
     (Position < Text'Length
      and then UTF8_Length (Text, Position) > 0
      and then Is_Client_Scalar (UTF8_Scalar (Text, Position)))
   with Pre => Text'Length <= SMB.Maximum_Frame_Size;

   --  D91 and Table 3-5 (UTF-16 Bit Distribution): a scalar up to FFFF is
   --  one 16-bit unit, itself; a larger one is two, 110110wwwwxxxxxx
   --  110111xxxxxxxxxx with wwww = uuuuu - 1, that is D800 plus the top ten
   --  bits of the scalar minus 10000, then DC00 plus its low ten bits.
   function UTF16_Units (Scalar : Natural) return Positive is
     (if Scalar <= 16#FFFF# then 1 else 2)
   with Pre => Is_Scalar (Scalar);

   function UTF16_Unit (Scalar : Natural; Index : Natural) return Natural is
     (if Scalar <= 16#FFFF# then Scalar
      elsif Index = 0 then 16#D800# + (Scalar - 16#10000#) / 1_024
      else 16#DC00# + (Scalar - 16#10000#) mod 1_024)
   with Pre => Is_Scalar (Scalar) and then Index < UTF16_Units (Scalar),
     Post => UTF16_Unit'Result <= 16#FFFF#;

   --  Byte Index of the scalar's UTF-16 units, little-endian.
   function UTF16_Byte (Scalar : Natural; Index : Natural) return SMB.Byte is
     (if Index mod 2 = 0 then SMB.Byte (UTF16_Unit (Scalar, Index / 2) mod 256)
      else SMB.Byte (UTF16_Unit (Scalar, Index / 2) / 256))
   with Pre =>
     Is_Scalar (Scalar) and then Index < 2 * UTF16_Units (Scalar);

   --  The bytes, from Position on, of the longest run of sequences that
   --  Valid_UTF8_At accepts: as many as the scan of a converter reads
   --  before the first one it refuses. The bodies of this and the other
   --  recursive functions are hidden from proofs; the implementation's
   --  lemmas unfold them a step at a time.
   function Valid_UTF8_Run (Text : String; Position : Natural) return Natural
   is
     (if not Valid_UTF8_At (Text, Position) then 0
      else UTF8_Length (Text, Position)
        + Valid_UTF8_Run (Text, Position + UTF8_Length (Text, Position)))
   with Pre =>
     Text'Length <= SMB.Maximum_Frame_Size and then Position <= Text'Length,
     Post => Valid_UTF8_Run'Result <= Text'Length - Position,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Text'Length - Position);

   --  The length in bytes of that run in UTF-16. Each UTF-8 sequence of n
   --  bytes is at most n units, so at most twice the bytes left (a bound
   --  that takes no recursion to check).
   function UTF16_Run_Size (Text : String; Position : Natural) return Natural
   is
     (if not Valid_UTF8_At (Text, Position) then 0
      else 2 * UTF16_Units (UTF8_Scalar (Text, Position))
        + UTF16_Run_Size (Text, Position + UTF8_Length (Text, Position)))
   with Pre =>
     Text'Length <= SMB.Maximum_Frame_Size and then Position <= Text'Length,
     Post => UTF16_Run_Size'Result <= 2 * (Text'Length - Position),
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Text'Length - Position);

   --  Byte Index of that run in UTF-16.
   function UTF16_Run_Byte
     (Text : String; Position : Natural; Index : Natural) return SMB.Byte is
     (if Index < 2 * UTF16_Units (UTF8_Scalar (Text, Position))
      then UTF16_Byte (UTF8_Scalar (Text, Position), Index)
      else UTF16_Run_Byte
        (Text, Position + UTF8_Length (Text, Position),
         Index - 2 * UTF16_Units (UTF8_Scalar (Text, Position))))
   with Pre =>
     Text'Length <= SMB.Maximum_Frame_Size
     and then Position <= Text'Length
     and then Index < UTF16_Run_Size (Text, Position),
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Text'Length - Position);
   pragma Annotate
     (GNATprove, Unhide_Info, "Expression_Function_Body", UTF16_Run_Size);

   --  Whether Data, from Offset to its end, is that run in UTF-16, scalar by
   --  scalar: the same bytes as UTF16_Run_Byte gives, in a form whose
   --  check at run time takes time linear in the run.
   function Is_UTF16_Run
     (Text : String; Position : Natural; Data : SMB.Bytes; Offset : Natural)
      return Boolean
   is
     (if not Valid_UTF8_At (Text, Position) then Offset = Data'Length
      else
        Data'Length - Offset >= 2 * UTF16_Units (UTF8_Scalar (Text, Position))
        and then
          (for all J in 0 .. 2 * UTF16_Units (UTF8_Scalar (Text, Position)) - 1
           => Data (Data'First + Offset + J) =
                UTF16_Byte (UTF8_Scalar (Text, Position), J))
        and then Is_UTF16_Run
          (Text, Position + UTF8_Length (Text, Position), Data,
           Offset + 2 * UTF16_Units (UTF8_Scalar (Text, Position))))
   with Pre =>
     Text'Length <= SMB.Maximum_Frame_Size
     and then Position <= Text'Length
     and then Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Offset <= Data'Length,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Text'Length - Position);

   --  Whether Text is well-formed UTF-8 of scalars this client converts.
   function Is_Client_UTF8 (Text : String) return Boolean is
     (Valid_UTF8_Run (Text, 0) = Text'Length)
   with Pre => Text'Length <= SMB.Maximum_Frame_Size;
end SMB.Spec.Unicode;
