#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/integration.hpp>

#include <stdio.h>
#include <fstream>

// todo: cleanup typedef'ing
//Note: libsnark::default_r1cs_ppzksnark_pp is libff::default_ec_pp
//typedef libsnark::default_r1cs_ppzksnark_pp ppzksnark_ppT;


// todo: Cleanup namespacing
//using namespace libsnark;
using namespace gadgetlib2;
using std::cout;
using std::endl;

//ProtoboardPtr
void test_AND_gadget(){
    initPublicParamsFromDefaultPp();
    cout << "Initialized public params" << endl;
    auto pb = Protoboard::create(R1P);
    cout << "Created Protoboard" << endl;

    VariableArray x(3, "x");
    Variable y("y");
    cout << "Created Variables" << endl;
    auto andGadget = AND_Gadget::create(pb, x, y);
    cout << "Created AND GADGET" << endl;
    andGadget->generateConstraints();
    cout << "Generated Constraints" << endl;
    /*
    pb->val(x[0]) = 0;
    pb->val(x[1]) = 1;
    pb->val(x[2]) = 1;
    andGadget->generateWitness();
    EXPECT_TRUE(pb->val(y) == 0);
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    pb->val(y) = 1;
    EXPECT_FALSE(pb->isSatisfied());

    pb->val(x[0]) = 1;
    andGadget->generateWitness();
    EXPECT_TRUE(pb->val(y) == 1);
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));

    pb->val(y) = 0;
    EXPECT_FALSE(pb->isSatisfied());
    */
}

void test_OR_gadget(){
    std::cout << "Enter create protoboard" << std::endl;
    // Initialize the field
    initPublicParamsFromDefaultPp();

    // Create a protoboard for a system of rank 1 constraints over a prime field.
    ProtoboardPtr pb = Protoboard::create(R1P);

    // <TEST>
    std::cout << "protoboard OR_Gadget variables" << std::endl;
    Variable input1("input1");
    Variable input2("input2");
    Variable result("result");
    std::cout << "protoboard OR_Gadget create(..)" << std::endl;
    GadgetPtr orGadget = OR_Gadget::create(pb, input1, input2, result);
    std::cout << "protoboard OR_Gadget generateConstraints()" << std::endl;
    orGadget->generateConstraints();
    std::cout << "protoboard OR_Gadget complete" << std::endl;
    // </TEST>
    //return pb;
}

int main () {
    std::cout << "Enter Main" << std::endl;

    test_AND_gadget();
    test_OR_gadget();

    std::cout << "Exit Main" << std::endl;
    return 0;
}
