with Ada.Finalization;
with Ada.Strings.Unbounded;
with SMB.Engine;
with SMB.Transport;

package SMB.Client is
   type Connection is new Ada.Finalization.Limited_Controlled with private;
   type Handle is limited private;

   type Entropy_Source is access procedure (Output : out SMB.Bytes);
   type Access_Mode is (Read_Only, Write_Only, Read_Write);
   type Create_Disposition is
     (Open_Existing, Create_New, Open_Or_Create, Truncate_Existing,
      Create_Or_Truncate);

   --  The dialects Connect offers. SMB 3.1.1 protects the negotiation with
   --  its preauth integrity hash; offering 2.1 as well lets an active
   --  attacker strip 3.1.1 from the request and force 2.1.
   type Dialect_Policy is (SMB_311_Only, SMB_311_Or_21);

   type Directory_Entry is record
      Name : Ada.Strings.Unbounded.Unbounded_String;
      Size : SMB.QWord := 0;
      Attributes : SMB.DWord := 0;
   end record;
   type Directory_Entry_Array is array (Natural range <>) of Directory_Entry;

   procedure Connect
     (Client : in out Connection;
      Host : String;
      Port : Positive := 445;
      Timeout_Seconds : Duration := 10.0;
      Entropy : Entropy_Source := null;
      Dialects : Dialect_Policy := SMB_311_Only;
      Require_Encryption : Boolean := False);
   procedure Authenticate
     (Client : in out Connection;
      User, Password : String;
      Domain : String := "");
   procedure Connect_Share (Client : in out Connection; Share : String);

   function Open_File
     (Client : in out Connection;
      Path : String;
      Mode : Access_Mode := Read_Only;
      Disposition : Create_Disposition := Open_Existing) return Handle;
   function Read
     (Client : in out Connection;
      File : Handle;
      Offset : SMB.QWord;
      Length : Positive) return SMB.Bytes;
   procedure Write
     (Client : in out Connection;
      File : Handle;
      Offset : SMB.QWord;
      Data : SMB.Bytes);
   procedure Close (Client : in out Connection; File : in out Handle);

   function List_Directory
     (Client : in out Connection;
      Path : String := "") return Directory_Entry_Array;
   procedure Make_Directory (Client : in out Connection; Path : String);
   procedure Remove_File (Client : in out Connection; Path : String);
   procedure Remove_Directory (Client : in out Connection; Path : String);
   procedure Rename (Client : in out Connection; Old_Path, New_Path : String);
   procedure Disconnect (Client : in out Connection);

   function Last_NT_Status (Client : Connection) return SMB.DWord;
   --  Diagnostic only: unauthenticated peer claim, never a trusted NTSTATUS.
   --  Zero means absent. Cleared by Connect or Disconnect.
   function Last_Unverified_Authentication_Status
     (Client : Connection) return SMB.DWord;
   function Is_Connected (Client : Connection) return Boolean;
   --  The dialect Connect negotiated, 16#0311# or 16#0210#; 0 before it.
   function Negotiated_Dialect (Client : Connection) return SMB.Word;
   --  Whether requests and responses are encrypted. A 3.1.1 connection
   --  whose negotiation chose a cipher encrypts everything once Authenticate
   --  succeeds; Connect with Require_Encryption fails when there is no
   --  cipher.
   function Is_Encrypted (Client : Connection) return Boolean;
   overriding procedure Finalize (Client : in out Connection);

private
   type Connection is new Ada.Finalization.Limited_Controlled with record
      Channel : SMB.Transport.Connection;
      Engine_Core : SMB.Engine.Engine_State;
      Host : Ada.Strings.Unbounded.Unbounded_String;
      Entropy : Entropy_Source := null;
      Last_Status : SMB.DWord := SMB.Success;
      Unverified_Authentication_Status : SMB.DWord := 0;
   end record;

   type Handle is limited record
      Engine_Token : SMB.Engine.Handle_Token;
   end record;
end SMB.Client;
