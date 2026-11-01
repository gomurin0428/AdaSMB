with Interfaces;

package SMB.Crypto is
   pragma SPARK_Mode (On);
   pragma Unevaluated_Use_Of_Old (Allow);

   Maximum_Hash_Input : constant :=
     SMB.Maximum_Frame_Size + 64;

   subtype Digest_128 is SMB.Bytes (0 .. 15);
   subtype Digest_256 is SMB.Bytes (0 .. 31);

   function MD4 (Message : SMB.Bytes) return Digest_128
   with Pre => Message'Length <= Maximum_Hash_Input;

   function MD5 (Message : SMB.Bytes) return Digest_128
   with Pre => Message'Length <= Maximum_Hash_Input;

   function SHA256 (Message : SMB.Bytes) return Digest_256
   with Pre => Message'Length <= Maximum_Hash_Input;

   function HMAC_MD5 (Key, Message : SMB.Bytes) return Digest_128
   with Pre =>
     Key'Length <= SMB.Maximum_Frame_Size
     and Message'Length <= SMB.Maximum_Frame_Size;

   function HMAC_SHA256 (Key, Message : SMB.Bytes) return Digest_256
   with Pre =>
     Key'Length <= SMB.Maximum_Frame_Size
     and Message'Length <= SMB.Maximum_Frame_Size;

   --  Incremental HMAC-SHA256: the message is absorbed in pieces in 64-byte
   --  blocks, so neither the message nor a concatenated copy is kept.
   type HMAC_SHA256_Context is private;

   function HMAC_SHA256_Ready (Context : HMAC_SHA256_Context) return Boolean;
   function HMAC_SHA256_Length (Context : HMAC_SHA256_Context) return Natural;

   procedure HMAC_SHA256_Start
     (Context : out HMAC_SHA256_Context;
      Key : SMB.Bytes)
   with Pre => Key'Length <= SMB.Maximum_Frame_Size,
     Post => HMAC_SHA256_Ready (Context)
       and then HMAC_SHA256_Length (Context) = 0;

   procedure HMAC_SHA256_Update
     (Context : in out HMAC_SHA256_Context;
      Message : SMB.Bytes)
   with Pre => HMAC_SHA256_Ready (Context)
       and then Message'Length <= SMB.Maximum_Frame_Size
       and then HMAC_SHA256_Length (Context) <=
         SMB.Maximum_Frame_Size - Message'Length,
     Post => HMAC_SHA256_Ready (Context)
       and then HMAC_SHA256_Length (Context) =
         HMAC_SHA256_Length (Context)'Old + Message'Length;

   procedure HMAC_SHA256_Finish
     (Context : in out HMAC_SHA256_Context;
      Digest : out Digest_256)
   with Pre => HMAC_SHA256_Ready (Context),
     Post => not HMAC_SHA256_Ready (Context);

   -- Keep the potentially short-circuiting equality oracle proof-only.
   pragma Assertion_Policy (Post => Ignore);
   function Constant_Time_Equal (Left, Right : SMB.Bytes) return Boolean
   with Pre =>
     Left'Length <= Maximum_Hash_Input
     and Right'Length <= Maximum_Hash_Input,
     Post => Constant_Time_Equal'Result = (Left = Right);
private
   type Hash_State is array (Natural range 0 .. 7) of Interfaces.Unsigned_32;
   subtype Block_Position is Natural range 0 .. 63;

   type SHA256_Context is record
      H : Hash_State := (others => 0);
      Block : SMB.Bytes (0 .. 63) := (others => 0);
      Used : Block_Position := 0;
      Total : Natural := 0;
   end record;

   type HMAC_SHA256_Context is record
      Inner : SHA256_Context;
      Outer_Pad : SMB.Bytes (0 .. 63) := (others => 0);
      Length : Natural := 0;
   end record;

   function HMAC_SHA256_Ready (Context : HMAC_SHA256_Context) return Boolean is
     (Context.Length <= SMB.Maximum_Frame_Size
      and then Context.Inner.Total = Context.Length + 64);

   function HMAC_SHA256_Length (Context : HMAC_SHA256_Context) return Natural is
     (Context.Length);
end SMB.Crypto;
