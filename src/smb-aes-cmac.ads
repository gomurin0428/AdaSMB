--  AES-128-CMAC (RFC 4493, NIST SP 800-38B), the SMB 3.x signing MAC
--  (MS-SMB2 3.1.4.1): the signature is the whole 16-byte tag over the
--  message with its Signature field zeroed.
--
--  The incremental form lets a caller feed a frame as its header, a zero
--  signature and the rest without copying them together. CMAC treats the
--  final block differently (K1 when it is complete, padding and K2 when it
--  is not), so Update keeps the last 1 to 16 bytes of a nonempty message
--  buffered and Finish processes them.
--
--  The subkey doubling scales its reduction constant by the carried bit and
--  the padding depends only on the message length, so no branch or table
--  index depends on the key or the message bytes. That is a coding rule,
--  not a proved property: the proof covers run-time safety and the
--  contracts below, and the known-answer and differential tests cover the
--  results. Finish wipes the context. MAC does not wipe its own local
--  context, and copies that the compiler leaves on the stack are not wiped
--  either.
package SMB.AES.CMAC is
   pragma SPARK_Mode (On);
   pragma Unevaluated_Use_Of_Old (Allow);

   subtype Tag_128 is SMB.Bytes (0 .. 15);

   function MAC (Key : Key_128; Message : SMB.Bytes) return Tag_128
   with Pre => Message'Length <= SMB.Maximum_Frame_Size;

   --  A default context is empty, wiped and not Ready.
   type MAC_Context is private;

   function Ready (Context : MAC_Context) return Boolean;
   function Length (Context : MAC_Context) return Natural;
   --  True when the context holds no key material and no message state.
   function Wiped (Context : MAC_Context) return Boolean;

   --  Starts a message, discarding any unfinished one.
   procedure Start (Context : out MAC_Context; Key : Key_128)
   with Post => Ready (Context) and then Length (Context) = 0;

   procedure Update (Context : in out MAC_Context; Message : SMB.Bytes)
   with Pre => Ready (Context)
       and then Message'Length <= SMB.Maximum_Frame_Size
       and then Length (Context) <= SMB.Maximum_Frame_Size - Message'Length,
     Post => Ready (Context)
       and then Length (Context) = Length (Context)'Old + Message'Length;

   procedure Finish (Context : in out MAC_Context; Tag : out Tag_128)
   with Pre => Ready (Context),
     Post => not Ready (Context) and then Wiped (Context);

private
   subtype Buffer_Count is Natural range 0 .. Block'Length;

   --  Started means holding an expanded key schedule: the default and the
   --  wiped context hold the unexpanded one.
   type MAC_Context is record
      Schedule : Key_Schedule;
      Subkey_1 : Block := (others => 0);
      Subkey_2 : Block := (others => 0);
      --  The CBC chaining value of the blocks processed so far.
      Chain : Block := (others => 0);
      --  The last Used bytes of the message, not yet processed.
      Buffer : Block := (others => 0);
      Used : Buffer_Count := 0;
      Total : Natural := 0;
   end record;

   --  Every component at its default: zeros and an unexpanded schedule.
   Cleared : constant MAC_Context := (others => <>);

   --  A nonempty message always leaves its last block in Buffer: Update
   --  processes a full buffer only when another byte follows it.
   function Ready (Context : MAC_Context) return Boolean is
     (SMB.AES.Ready (Context.Schedule)
      and then Context.Total <= SMB.Maximum_Frame_Size
      and then (Context.Used = 0) = (Context.Total = 0));

   function Length (Context : MAC_Context) return Natural is
     (Context.Total);

   function Wiped (Context : MAC_Context) return Boolean is
     (Context = Cleared);
end SMB.AES.CMAC;
