with SMB.Spec.SHA2.Lemmas;

package body SMB.Core_Preauth is
   pragma SPARK_Mode (On);
   package SHA2 renames SMB.Spec.SHA2;
   package SHA2_Lemmas renames SMB.Spec.SHA2.Lemmas;

   procedure Update (Value : in out Hash_Value; Message : SMB.Bytes) is
      --  The model's states between the calls, and the lemmas that join
      --  the two pieces and finish them; none of it runs.
      pragma Assertion_Policy (Ghost => Ignore);
      Previous : constant Hash_Value := Value with Ghost;
      Context : SMB.Crypto.SHA512_Context;
   begin
      SMB.Crypto.SHA512_Start (Context);
      declare
         Started : constant SHA2.State_512 :=
           SMB.Crypto.SHA512_State (Context)
         with Ghost;
      begin
         SMB.Crypto.SHA512_Update (Context, Value);
         SHA2_Lemmas.Lemma_Absorb_Equal_512
           (Started, SHA2.Start_512, Previous, Previous'Length);
      end;
      declare
         First : constant SHA2.State_512 := SMB.Crypto.SHA512_State (Context)
         with Ghost;
      begin
         SMB.Crypto.SHA512_Update (Context, Message);
         SHA2_Lemmas.Lemma_Absorb_Equal_512
           (First, SHA2.Absorb_512 (SHA2.Start_512, Previous), Message,
            Message'Length);
         SHA2_Lemmas.Lemma_Absorb_Join_512 (SHA2.Start_512, Previous, Message);
      end;
      declare
         Both : constant SHA2.State_512 := SMB.Crypto.SHA512_State (Context)
         with Ghost;
      begin
         SMB.Crypto.SHA512_Finish (Context, Value);
         SHA2_Lemmas.Lemma_Finish_Equal_512
           (Both, SHA2.Absorb_512 (SHA2.Start_512, Previous & Message),
            Previous'Length + Message'Length);
      end;
      SHA2_Lemmas.Lemma_Finish_512 (Previous & Message);
   end Update;

end SMB.Core_Preauth;
