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

   subtype Digest_512 is SMB.Bytes (0 .. 63);

   function SHA512 (Message : SMB.Bytes) return Digest_512
   with Pre => Message'Length <= Maximum_Hash_Input;

   --  Incremental SHA-512, for the SMB 3.1.1 preauth integrity hash: the
   --  previous hash value and a whole message are hashed without first
   --  being copied together.
   type SHA512_Context is private;

   function SHA512_Ready (Context : SHA512_Context) return Boolean;
   function SHA512_Length (Context : SHA512_Context) return Natural;

   procedure SHA512_Start (Context : out SHA512_Context)
   with Post => SHA512_Ready (Context)
       and then SHA512_Length (Context) = 0;

   procedure SHA512_Update
     (Context : in out SHA512_Context;
      Message : SMB.Bytes)
   with Pre => SHA512_Ready (Context)
       and then Message'Length <= Maximum_Hash_Input
       and then SHA512_Length (Context) <=
         Maximum_Hash_Input - Message'Length,
     Post => SHA512_Ready (Context)
       and then SHA512_Length (Context) =
         SHA512_Length (Context)'Old + Message'Length;

   procedure SHA512_Finish
     (Context : in out SHA512_Context;
      Digest : out Digest_512)
   with Pre => SHA512_Ready (Context),
     Post => not SHA512_Ready (Context);

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

   --  Incremental HMAC-MD5, with the same contracts as HMAC-SHA256.
   type HMAC_MD5_Context is private;

   function HMAC_MD5_Ready (Context : HMAC_MD5_Context) return Boolean;
   function HMAC_MD5_Length (Context : HMAC_MD5_Context) return Natural;

   procedure HMAC_MD5_Start
     (Context : out HMAC_MD5_Context;
      Key : SMB.Bytes)
   with Pre => Key'Length <= SMB.Maximum_Frame_Size,
     Post => HMAC_MD5_Ready (Context)
       and then HMAC_MD5_Length (Context) = 0;

   procedure HMAC_MD5_Update
     (Context : in out HMAC_MD5_Context;
      Message : SMB.Bytes)
   with Pre => HMAC_MD5_Ready (Context)
       and then Message'Length <= SMB.Maximum_Frame_Size
       and then HMAC_MD5_Length (Context) <=
         SMB.Maximum_Frame_Size - Message'Length,
     Post => HMAC_MD5_Ready (Context)
       and then HMAC_MD5_Length (Context) =
         HMAC_MD5_Length (Context)'Old + Message'Length;

   procedure HMAC_MD5_Finish
     (Context : in out HMAC_MD5_Context;
      Digest : out Digest_128)
   with Pre => HMAC_MD5_Ready (Context),
     Post => not HMAC_MD5_Ready (Context);

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

   type Hash_State_64 is
     array (Natural range 0 .. 7) of Interfaces.Unsigned_64;
   subtype Block_Position_128 is Natural range 0 .. 127;

   type SHA512_Context is record
      H : Hash_State_64 := (others => 0);
      Block : SMB.Bytes (0 .. 127) := (others => 0);
      Used : Block_Position_128 := 0;
      Total : Natural := 0;
      Active : Boolean := False;
   end record;

   function SHA512_Ready (Context : SHA512_Context) return Boolean is
     (Context.Active and then Context.Total <= Maximum_Hash_Input);

   function SHA512_Length (Context : SHA512_Context) return Natural is
     (Context.Total);

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

   type MD5_State is array (Natural range 0 .. 3) of Interfaces.Unsigned_32;

   type MD5_Context is record
      H : MD5_State := (others => 0);
      Block : SMB.Bytes (0 .. 63) := (others => 0);
      Used : Block_Position := 0;
      Total : Natural := 0;
   end record;

   type HMAC_MD5_Context is record
      Inner : MD5_Context;
      Outer_Pad : SMB.Bytes (0 .. 63) := (others => 0);
      Length : Natural := 0;
   end record;

   function HMAC_MD5_Ready (Context : HMAC_MD5_Context) return Boolean is
     (Context.Length <= SMB.Maximum_Frame_Size
      and then Context.Inner.Total = Context.Length + 64);

   function HMAC_MD5_Length (Context : HMAC_MD5_Context) return Natural is
     (Context.Length);
end SMB.Crypto;
