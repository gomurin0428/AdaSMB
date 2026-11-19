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
with SMB.Spec.SMB2;

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
   --  MS-SMB2 2.2.1.2: the SYNC header, on the WRITE and READ requests and
   --  responses of Microsoft's "SMB 3.1.1 Encryption in Windows 10" blog,
   --  appendix A.2 (the messages test_suite decrypts).
   procedure Test_SMB2_Header is
      package S renames SMB.Spec.SMB2;
      use type S.Sync_Header;
      Write_Request : constant SMB.Bytes :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#09#, 16#00#, 16#01#, 16#00#,
         16#08#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#05#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#01#, 16#00#, 16#00#, 16#00#,
         16#21#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         --  The start of the WRITE request's body: StructureSize 49.
         16#31#, 16#00#);
      Read_Response : constant SMB.Bytes (1000 .. 1063) :=
        (16#FE#, 16#53#, 16#4D#, 16#42#, 16#40#, 16#00#, 16#01#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#08#, 16#00#, 16#01#, 16#00#,
         16#01#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#06#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FE#, 16#00#, 16#00#, 16#01#, 16#00#, 16#00#, 16#00#,
         16#21#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#);
      Write_Header : constant S.Sync_Header :=
        (Credit_Charge => 1, Status => 0, Command => S.Write, Credits => 1,
         Flags => S.Flags_Signed, Next_Command => 0, Message_Id => 5,
         Reserved => 16#FEFF#, Tree_Id => 1,
         Session_Id => 16#0000_1000_0000_0021#, Signature => (others => 0))
      with Ghost;
      Read_Header : constant S.Sync_Header :=
        (Write_Header with delta
           Command => S.Read, Flags => S.Flags_Server_To_Redir,
           Message_Id => 6)
      with Ghost;
   begin
      pragma Assert (S.Is_Sync_Header (Write_Request, Write_Header),
                     "the WRITE request's header");
      Passed;
      pragma Assert (S.Is_Sync_Header (Read_Response, Read_Header),
                     "the READ response's header, at other bounds");
      Passed;
      --  Every field is read where 2.2.1.2 puts it: a change to any one
      --  value no longer matches.
      pragma Assert
        (not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Credit_Charge => 2))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Status => 1))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Command => S.Read))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Credits => 2))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Flags => 0))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Next_Command => 64))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Message_Id => 2 ** 32 + 5))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Reserved => 0))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Tree_Id => 2))
         and then not S.Is_Sync_Header
           (Write_Request, (Write_Header with delta Session_Id => 16#21#))
         and then not S.Is_Sync_Header
           (Write_Request,
            (Write_Header with delta Signature => (15 => 1, others => 0))),
         "each field");
      Passed;
      --  A header needs all 64 bytes.
      pragma Assert
        (not S.Is_Sync_Header
           (Write_Request (Write_Request'First .. Write_Request'First + 62),
            Write_Header),
         "63 bytes");
      Passed;
      --  A client's own request: no status, NextCommand or Reserved, and
      --  the Signature zero until signing fills it in.
      pragma Assert
        (S.Request_Header
           (Command => S.Write, Credit_Charge => 1, Credit_Request => 1,
            Flags => S.Flags_Signed, Message_Id => 5, Tree_Id => 1,
            Session_Id => 16#0000_1000_0000_0021#)
         = (Write_Header with delta Reserved => 0),
         "Request_Header");
      Passed;
   end Test_SMB2_Header;
begin
   Test_Encoding;
   Test_SMB2_Header;
   Ada.Text_IO.Put_Line
     ("specification tests passed:" & Natural'Image (Checks) & " checks");
end Spec_Test;
