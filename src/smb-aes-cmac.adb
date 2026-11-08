with Interfaces;

package body SMB.AES.CMAC is
   pragma SPARK_Mode (On);

   use type Interfaces.Unsigned_8;

   --  Every helper has a contract, if only Post => True, so that GNATprove
   --  proves it once and its callers see only the contract (see SMB.AES).

   Zero_Block : constant Block := (others => 0);

   --  Multiplication by x in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1,
   --  with the block as a big-endian number: shift left one bit, and xor
   --  16#87# into the last byte when the top bit falls off. The top bit
   --  scales the constant instead of selecting it with a branch.
   function Double (Value : Block) return Block
     with Post => True
   is
      Result : Block;
   begin
      for I in Block'Range loop
         Result (I) := Interfaces.Shift_Left (Value (I), 1)
           or (if I = Block'Last then 0
               else Interfaces.Shift_Right (Value (I + 1), 7));
      end loop;
      Result (Block'Last) := Result (Block'Last)
        xor 16#87# * Interfaces.Shift_Right (Value (Block'First), 7);
      return Result;
   end Double;

   function Xor_Block (Left, Right : Block) return Block
     with Post => True
   is
      Result : Block;
   begin
      for I in Block'Range loop
         Result (I) := Left (I) xor Right (I);
      end loop;
      return Result;
   end Xor_Block;

   --  The first Count bytes of Data, then 16#80#, then zeros.
   function Padded (Data : Block; Count : Natural) return Block
     with Pre => Count < Block'Length,
       Post => True
   is
      Result : Block;
   begin
      for I in Block'Range loop
         Result (I) :=
           (if I < Count then Data (I) elsif I = Count then 16#80# else 0);
      end loop;
      return Result;
   end Padded;

   procedure Start (Context : out MAC_Context; Key : Key_128) is
      Schedule : Key_Schedule;
   begin
      Expand_Key (Key, Schedule);
      declare
         Subkey_1 : constant Block :=
           Double (Encrypt (Schedule, Zero_Block));
      begin
         Context :=
           (Schedule => Schedule,
            Subkey_1 => Subkey_1,
            Subkey_2 => Double (Subkey_1),
            Chain => Zero_Block,
            Buffer => Zero_Block,
            Used => 0,
            Total => 0);
      end;
   end Start;

   procedure Update (Context : in out MAC_Context; Message : SMB.Bytes) is
   begin
      for I in Message'Range loop
         --  A full buffer is a complete block that is not the last one.
         if Context.Used = Block'Length then
            Context.Chain := Encrypt
              (Context.Schedule, Xor_Block (Context.Chain, Context.Buffer));
            Context.Used := 0;
         end if;
         Context.Buffer (Context.Used) := Message (I);
         Context.Used := Context.Used + 1;
         pragma Loop_Invariant (Context.Used >= 1);
         pragma Loop_Invariant (Context.Total = Context.Total'Loop_Entry);
         pragma Loop_Invariant (SMB.AES.Ready (Context.Schedule));
      end loop;
      Context.Total := Context.Total + Message'Length;
   end Update;

   --  The tag of the message absorbed so far: its last block masked with K1
   --  when the block is complete, padded and masked with K2 when it is not.
   function Final_Tag (Context : MAC_Context) return Tag_128
     with Pre => Ready (Context),
       Post => True
   is
      Last : Block;
   begin
      if Context.Used = Block'Length then
         Last := Xor_Block (Context.Buffer, Context.Subkey_1);
      else
         Last := Xor_Block
           (Padded (Context.Buffer, Context.Used), Context.Subkey_2);
      end if;
      return Encrypt (Context.Schedule, Xor_Block (Context.Chain, Last));
   end Final_Tag;

   procedure Finish (Context : in out MAC_Context; Tag : out Tag_128) is
   begin
      Tag := Final_Tag (Context);
      Context := Cleared;
   end Finish;

   function MAC (Key : Key_128; Message : SMB.Bytes) return Tag_128 is
      Context : MAC_Context;
   begin
      Start (Context, Key);
      Update (Context, Message);
      return Final_Tag (Context);
   end MAC;

end SMB.AES.CMAC;
