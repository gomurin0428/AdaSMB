--  The specification packages (SMB.Spec.*) run on their own, on published
--  vectors and on properties that follow from the standards. GNATprove ties
--  the core's code to the specifications; this program ties the
--  specifications to the standards. It uses nothing from the implementation.
--
--  Ghost functions can be called only from ghost code and assertions, so each
--  check is a pragma Assert (checked: this program needs the assertion
--  policy Check), followed by Passed, which counts it.
pragma Assertion_Policy (Assert => Check, Ghost => Check);

with Ada.Text_IO;
with Interfaces;
with SMB;
with SMB.Spec.Encoding;

procedure Spec_Test is
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Checks : Natural := 0;

   procedure Passed is
   begin
      Checks := Checks + 1;
   end Passed;

   --  MS-SMB2 and MS-DTYP: little-endian unsigned integers.
   procedure Test_Encoding is
      package E renames SMB.Spec.Encoding;
      --  The header of the WRITE request in Microsoft's "SMB 3.1.1
      --  Encryption in Windows 10" blog, appendix A.2 (the message
      --  test_suite decrypts): ProtocolId FE 'S' 'M' 'B', StructureSize 64,
      --  CreditCharge 1, Status 0, Command WRITE (9), CreditRequest 1, Flags
      --  SMB2_FLAGS_SIGNED, NextCommand 0, MessageId 5, Reserved 0xFEFF,
      --  TreeId 1, SessionId 0x0000100000000021, Signature 0.
      Header : constant SMB.Bytes :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#09#, 16#00#, 16#01#, 16#00#,
         16#08#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#05#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#01#, 16#00#, 16#00#, 16#00#,
         16#21#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#);
      Shifted : constant SMB.Bytes (100 .. 163) := Header;
      Values : constant array (Positive range <>) of SMB.QWord :=
        (0, 1, 16#FF#, 16#100#, 16#FFFF#, 16#1_0000#, 16#FFFF_FFFF#,
         16#1_0000_0000#, 16#0123_4567_89AB_CDEF#, 16#8000_0000_0000_0000#,
         SMB.QWord'Last);
      Encoded : SMB.Bytes (0 .. 7) with Ghost;

      procedure Encode (Value : SMB.QWord) with Ghost is
      begin
         for Index in Encoded'Range loop
            Encoded (Index) := E.LE_Byte (Value, Index);
         end loop;
      end Encode;
   begin
      pragma Assert (E.LE32 (Header, 0) = 16#424D_53FE#, "ProtocolId");
      Passed;
      pragma Assert (E.LE16 (Header, 4) = 64, "StructureSize");
      Passed;
      pragma Assert (E.LE16 (Header, 6) = 1, "CreditCharge");
      Passed;
      pragma Assert (E.LE32 (Header, 8) = 0, "Status");
      Passed;
      pragma Assert (E.LE16 (Header, 12) = 9, "Command");
      Passed;
      pragma Assert (E.LE16 (Header, 14) = 1, "CreditRequest");
      Passed;
      pragma Assert (E.LE32 (Header, 16) = 8, "Flags");
      Passed;
      pragma Assert (E.LE64 (Header, 24) = 5, "MessageId");
      Passed;
      pragma Assert (E.LE32 (Header, 32) = 16#FEFF#, "Reserved");
      Passed;
      pragma Assert (E.LE32 (Header, 36) = 1, "TreeId");
      Passed;
      pragma Assert
        (E.LE64 (Header, 40) = 16#0000_1000_0000_0021#, "SessionId");
      Passed;
      --  Offsets count from Data'First, whatever it is.
      pragma Assert
        (E.LE16 (Shifted, 4) = 64
         and then E.LE64 (Shifted, 40) = 16#0000_1000_0000_0021#,
         "offsets from Data'First");
      Passed;
      --  LE_Byte is the inverse of LE64, and shorter reads give the low bits.
      for Value of Values loop
         Encode (Value);
         pragma Assert (E.LE64 (Encoded, 0) = Value, "LE_Byte then LE64");
         Passed;
         pragma Assert
           (E.LE32 (Encoded, 0) = SMB.DWord (Value mod 2 ** 32)
            and then E.LE16 (Encoded, 0) = SMB.Word (Value mod 2 ** 16),
            "shorter reads are the low bits");
         Passed;
      end loop;
   end Test_Encoding;
begin
   Test_Encoding;
   Ada.Text_IO.Put_Line
     ("specification tests passed:" & Natural'Image (Checks) & " checks");
end Spec_Test;
