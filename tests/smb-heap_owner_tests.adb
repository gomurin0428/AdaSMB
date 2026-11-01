with Ada.Text_IO;
with System.Storage_Elements;
with System.Storage_Pools;
with SMB.Heap_Owner;

package body SMB.Heap_Owner_Tests is
   use System.Storage_Elements;

   procedure Assert (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
   end Assert;

   --  Serves allocations from a fixed arena and counts the live ones, so the
   --  tests can see whether an owner freed its object.
   type Counting_Pool is new System.Storage_Pools.Root_Storage_Pool with record
      Arena : Storage_Array (1 .. 4_096);
      Next : Storage_Offset := 1;
      Live : Integer := 0;
   end record;

   overriding procedure Allocate
     (Pool : in out Counting_Pool;
      Address : out System.Address;
      Size : Storage_Count;
      Alignment : Storage_Count);

   overriding procedure Deallocate
     (Pool : in out Counting_Pool;
      Address : System.Address;
      Size : Storage_Count;
      Alignment : Storage_Count);

   overriding function Storage_Size (Pool : Counting_Pool) return Storage_Count
   is (Pool.Arena'Length);

   overriding procedure Allocate
     (Pool : in out Counting_Pool;
      Address : out System.Address;
      Size : Storage_Count;
      Alignment : Storage_Count) is
      Start : Storage_Offset := Pool.Next;
   begin
      while To_Integer (Pool.Arena (Start)'Address)
        mod Integer_Address (Alignment) /= 0
      loop
         Start := Start + 1;
      end loop;
      if Start + Size - 1 > Pool.Arena'Last then
         raise Storage_Error with "heap owner test arena exhausted";
      end if;
      Address := Pool.Arena (Start)'Address;
      Pool.Next := Start + Size;
      Pool.Live := Pool.Live + 1;
   end Allocate;

   overriding procedure Deallocate
     (Pool : in out Counting_Pool;
      Address : System.Address;
      Size : Storage_Count;
      Alignment : Storage_Count)
   is
      pragma Unreferenced (Address, Size, Alignment);
   begin
      Pool.Live := Pool.Live - 1;
   end Deallocate;

   Pool : Counting_Pool;
   type Bytes_Access is access SMB.Bytes with Storage_Pool => Pool;

   Cleared : Natural := 0;

   procedure Count_Clear (Item : in out SMB.Bytes) is
   begin
      Item := (others => 0);
      Cleared := Cleared + 1;
   end Count_Clear;

   package Plain_Owners is new SMB.Heap_Owner (SMB.Bytes, Bytes_Access);
   package Clearing_Owners is new SMB.Heap_Owner
     (SMB.Bytes, Bytes_Access, Count_Clear);

   procedure Run is
   begin
      declare
         Owned : Clearing_Owners.Owner;
      begin
         Owned.Item := new SMB.Bytes'(1 .. 16 => 16#AA#);
         Assert (Pool.Live = 1 and then Owned.Item'Length = 16,
                 "heap owner allocation");
      end;
      Assert (Pool.Live = 0 and then Cleared = 1,
              "heap owner frees and clears on normal exit");

      begin
         declare
            Owned : Clearing_Owners.Owner;
         begin
            Owned.Item := new SMB.Bytes'(1 .. 16 => 16#AA#);
            if Owned.Item'Length = 16 then
               raise Constraint_Error with "heap owner test exception";
            end if;
         end;
      exception
         when Constraint_Error =>
            null;
      end;
      Assert (Pool.Live = 0 and then Cleared = 2,
              "heap owner frees and clears when an exception propagates");

      declare
         Owned : Clearing_Owners.Owner;
      begin
         Owned.Item := new SMB.Bytes'(1 .. 16 => 16#AA#);
         Clearing_Owners.Release (Owned);
         Assert (Owned.Item = null and then Pool.Live = 0 and then Cleared = 3,
                 "heap owner early release");
      end;
      Assert (Pool.Live = 0 and then Cleared = 3,
              "released heap owner is not freed again");

      declare
         Empty : Clearing_Owners.Owner;
         Plain : Plain_Owners.Owner;
      begin
         Assert (Empty.Item = null, "heap owner starts empty");
         Plain.Item := new SMB.Bytes'(1 .. 16 => 16#AA#);
         Assert (Plain.Item'Length = 16 and then Pool.Live = 1,
                 "plain heap owner allocation");
      end;
      Assert (Pool.Live = 0 and then Cleared = 3,
              "plain and empty heap owners");
      Ada.Text_IO.Put_Line ("heap owner tests: 4 cases passed");
   end Run;
end SMB.Heap_Owner_Tests;
