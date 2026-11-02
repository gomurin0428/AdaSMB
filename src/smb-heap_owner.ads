with Ada.Finalization;

--  Owns one heap object of the non-SPARK I/O layer and frees it when the owner
--  goes out of scope, also when an exception propagates. Clear runs on the
--  object just before it is freed (for example to erase a token).
private generic
   type Object (<>) is limited private;
   type Object_Access is access Object;
   with procedure Clear (Item : in out Object) is null;
package SMB.Heap_Owner is
   type Owner is new Ada.Finalization.Limited_Controlled with record
      Item : Object_Access;
   end record;

   --  Frees the object early; Item is null afterwards.
   procedure Release (Self : in out Owner);

   overriding procedure Finalize (Self : in out Owner);
end SMB.Heap_Owner;
