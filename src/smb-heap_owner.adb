with Ada.Unchecked_Deallocation;

package body SMB.Heap_Owner is
   procedure Free is new Ada.Unchecked_Deallocation (Object, Object_Access);

   procedure Release (Self : in out Owner) is
   begin
      if Self.Item /= null then
         Clear (Self.Item.all);
         Free (Self.Item);
      end if;
   end Release;

   overriding procedure Finalize (Self : in out Owner) is
   begin
      Release (Self);
   end Finalize;
end SMB.Heap_Owner;
