--  The Unicode encoding forms the client converts between (The Unicode
--  Standard, Version 16.0, section 3.9 "Unicode Encoding Forms"): UTF-8,
--  the form of the caller's strings, whose Characters are its bytes, and
--  UTF-16, the form of the protocol's (MS-SMB2 2.2: "all textual strings
--  MUST be in Unicode version 5.0 format ... using the 16-bit Unicode
--  Transformation Format (UTF-16)"; the encoding forms of section 3.9 are
--  the same in 5.0 and 16.0), little-endian as every SMB2 field
--  (SMB.Spec.Encoding).
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
   --  11110uuu, and each later one 10 followed by six bits of the scalar
   --  (10uuzzzz, 10yyyyyy, 10xxxxxx); the scalar is their bits together.
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
   --  110111xxxxxxxxxx with wwww = uuuuu - 1: D800 plus the top ten bits of
   --  (scalar - 10000), then DC00 plus its low ten bits.
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

   --  The other way: UTF-16, little-endian, to UTF-8.

   --  The 16-bit code unit at unit Position of Data (2 bytes each).
   function Code_Unit (Data : SMB.Bytes; Position : Natural) return Natural is
     (Natural (Data (Data'First + 2 * Position))
      + 256 * Natural (Data (Data'First + 2 * Position + 1)))
   with Pre =>
     Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Position < Data'Length / 2,
     Post => Code_Unit'Result <= 16#FFFF#;

   --  D91: in UTF-16 a scalar up to FFFF is its own unit, and a larger one
   --  a high surrogate (D800..DBFF) then a low one (DC00..DFFF); any other
   --  surrogate is ill-formed. The length in units of the well-formed
   --  sequence at unit Position, or 0.
   function UTF16_Length (Data : SMB.Bytes; Position : Natural) return Natural
   is
     (if Code_Unit (Data, Position) not in 16#D800# .. 16#DFFF# then 1
      elsif Code_Unit (Data, Position) <= 16#DBFF#
        and then Position + 1 < Data'Length / 2
        and then Code_Unit (Data, Position + 1) in 16#DC00# .. 16#DFFF#
      then 2
      else 0)
   with Pre =>
     Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Position < Data'Length / 2,
     Post =>
       UTF16_Length'Result <= 2
       and then UTF16_Length'Result <= Data'Length / 2 - Position;

   --  Table 3-5 read back: the scalar the sequence encodes.
   function UTF16_Scalar (Data : SMB.Bytes; Position : Natural) return Natural
   is
     (if UTF16_Length (Data, Position) = 1 then Code_Unit (Data, Position)
      else 16#10000#
        + (Code_Unit (Data, Position) - 16#D800#) * 1_024
        + (Code_Unit (Data, Position + 1) - 16#DC00#))
   with Pre =>
     Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Position < Data'Length / 2
     and then UTF16_Length (Data, Position) > 0,
     Post => Is_Scalar (UTF16_Scalar'Result);

   --  Whether a sequence of a scalar this client converts starts at unit
   --  Position.
   function Valid_UTF16_At
     (Data : SMB.Bytes; Position : Natural) return Boolean
   is
     (Position < Data'Length / 2
      and then UTF16_Length (Data, Position) > 0
      and then Is_Client_Scalar (UTF16_Scalar (Data, Position)))
   with Pre => Data'Length <= 2 * SMB.Maximum_Frame_Size;

   --  Table 3-6: the length of a scalar in UTF-8, and its bytes: the first
   --  0xxxxxxx, 110yyyyy, 1110zzzz or 11110uuu, each later one 10 and six
   --  bits.
   function UTF8_Size (Scalar : Natural) return Positive is
     (if Scalar <= 16#7F# then 1
      elsif Scalar <= 16#7FF# then 2
      elsif Scalar <= 16#FFFF# then 3
      else 4)
   with Pre => Is_Scalar (Scalar);

   function UTF8_Byte (Scalar : Natural; Index : Natural) return Natural is
     (case UTF8_Size (Scalar) is
         when 1 => Scalar,
         when 2 =>
           (if Index = 0 then 16#C0# + Scalar / 64
            else 16#80# + Scalar mod 64),
         when 3 =>
           (if Index = 0 then 16#E0# + Scalar / 4_096
            elsif Index = 1 then 16#80# + (Scalar / 64) mod 64
            else 16#80# + Scalar mod 64),
         when others =>
           (if Index = 0 then 16#F0# + Scalar / 262_144
            elsif Index = 1 then 16#80# + (Scalar / 4_096) mod 64
            elsif Index = 2 then 16#80# + (Scalar / 64) mod 64
            else 16#80# + Scalar mod 64))
   with Pre => Is_Scalar (Scalar) and then Index < UTF8_Size (Scalar),
     Post => UTF8_Byte'Result <= 16#FF#;

   --  The units, from unit Position on, of the longest run of sequences
   --  Valid_UTF16_At accepts.
   function Valid_UTF16_Run
     (Data : SMB.Bytes; Position : Natural) return Natural
   is
     (if not Valid_UTF16_At (Data, Position) then 0
      else UTF16_Length (Data, Position)
        + Valid_UTF16_Run (Data, Position + UTF16_Length (Data, Position)))
   with Pre =>
     Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Position <= Data'Length / 2,
     Post => Valid_UTF16_Run'Result <= Data'Length / 2 - Position,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Data'Length / 2 - Position);

   --  The length in bytes of that run in UTF-8: at most three bytes for a
   --  unit (a bound that takes no recursion to check).
   function UTF8_Run_Size (Data : SMB.Bytes; Position : Natural) return Natural
   is
     (if not Valid_UTF16_At (Data, Position) then 0
      else UTF8_Size (UTF16_Scalar (Data, Position))
        + UTF8_Run_Size (Data, Position + UTF16_Length (Data, Position)))
   with Pre =>
     Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Position <= Data'Length / 2,
     Post => UTF8_Run_Size'Result <= 3 * (Data'Length / 2 - Position),
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Data'Length / 2 - Position);

   --  Byte Index of that run in UTF-8.
   function UTF8_Run_Byte
     (Data : SMB.Bytes; Position : Natural; Index : Natural) return Natural is
     (if Index < UTF8_Size (UTF16_Scalar (Data, Position))
      then UTF8_Byte (UTF16_Scalar (Data, Position), Index)
      else UTF8_Run_Byte
        (Data, Position + UTF16_Length (Data, Position),
         Index - UTF8_Size (UTF16_Scalar (Data, Position))))
   with Pre =>
     Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Position <= Data'Length / 2
     and then Index < UTF8_Run_Size (Data, Position),
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Data'Length / 2 - Position);
   pragma Annotate
     (GNATprove, Unhide_Info, "Expression_Function_Body", UTF8_Run_Size);

   --  Whether Text, from Offset to its end, is that run in UTF-8, scalar by
   --  scalar, in a form linear to check.
   function Is_UTF8_Run
     (Data : SMB.Bytes; Position : Natural; Text : String; Offset : Natural)
      return Boolean
   is
     (if not Valid_UTF16_At (Data, Position) then Offset = Text'Length
      else
        Text'Length - Offset >= UTF8_Size (UTF16_Scalar (Data, Position))
        and then
          (for all J in 0 .. UTF8_Size (UTF16_Scalar (Data, Position)) - 1 =>
             Character'Pos (Text (Text'First + Offset + J)) =
               UTF8_Byte (UTF16_Scalar (Data, Position), J))
        and then Is_UTF8_Run
          (Data, Position + UTF16_Length (Data, Position), Text,
           Offset + UTF8_Size (UTF16_Scalar (Data, Position))))
   with Pre =>
     Data'Length <= 2 * SMB.Maximum_Frame_Size
     and then Position <= Data'Length / 2
     and then Text'Length <= 2 * SMB.Maximum_Frame_Size
     and then Offset <= Text'Length,
     Annotate => (GNATprove, Hide_Info, "Expression_Function_Body"),
     Subprogram_Variant => (Decreases => Data'Length / 2 - Position);

   --  Whether Data is well-formed UTF-16 of scalars this client converts.
   function Is_Client_UTF16 (Data : SMB.Bytes) return Boolean is
     (Data'Length mod 2 = 0
      and then Valid_UTF16_Run (Data, 0) = Data'Length / 2)
   with Pre => Data'Length <= 2 * SMB.Maximum_Frame_Size;
end SMB.Spec.Unicode;
