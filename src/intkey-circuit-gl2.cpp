#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/integration.hpp>

#include <stdio.h>
#include <fstream>

std::string PKPATH = "proving.key";
std::string VKPATH = "verification.key";

// todo: cleanup typedef'ing
//Note: libsnark::default_r1cs_ppzksnark_pp is libff::default_ec_pp
typedef libsnark::default_r1cs_ppzksnark_pp ppzksnark_ppT;


// todo: Cleanup namespacing
using namespace libsnark;
using namespace gadgetlib2;
using std::cout;
using std::endl;

/* This is a placeholder circuit until the comparison gadget is fixed */
ProtoboardPtr create_intkey_placeholder_protoboard(){
    cout << "Enter create placeholder protoboard" << endl;

    initPublicParamsFromDefaultPp();

    ProtoboardPtr pb = Protoboard::create(R1P);

    VariableArray a(3, "a");
    Variable b("b");

    cout << "Create AND_gadget" << endl;
    GadgetPtr andGadget = AND_Gadget::create(pb, a, b);

    cout << "Generate Constraints" << endl;
    andGadget->generateConstraints();
    return pb;
}

/* TODO: the comparison gadget segfaults. need to root cause and resolve with libsnark before
   using this method */
ProtoboardPtr create_intkey_set_protoboard(){
    cout << "Enter create protoboard" << endl;
    // Initialize the field
    initPublicParamsFromDefaultPp();

    ProtoboardPtr pb = Protoboard::create(R1P);

    // Add "intkey set" constraint to pb
    // Valid Values must be integers in the range of 0 through 232 - 1 (32-bit unsigned int)
    size_t wbs_lt;
    PackedWord lhs_lt, rhs_lt;
    FlagVariable less_lt, lessOrEqual_lt;

    GadgetPtr lessThanMax =
        Comparison_Gadget::create(pb, wbs_lt, lhs_lt, rhs_lt, less_lt, lessOrEqual_lt);

    lessThanMax->generateConstraints();

    size_t wbs_gt;
    PackedWord lhs_gt, rhs_gt;
    FlagVariable less_gt, lessOrEqual_gt;

    GadgetPtr greaterThanMin=
        Comparison_Gadget::create(pb, wbs_gt, lhs_gt, rhs_gt, less_gt, lessOrEqual_gt);
    greaterThanMin->generateConstraints();

    return pb;
}

template<typename ppT>
void generator()
{
    cout << "Enter generator" << endl;
    ProtoboardPtr pb = create_intkey_placeholder_protoboard();//create_intkey_set_protoboard();

    cout << "Extract Constraint System" << endl;
    r1cs_constraint_system<Fp> cs = get_constraint_system_from_gadgetlib2(*pb);
    cout << "Generate Key Pair" << endl;
    // This prints a whole bunch of junk. Look into squelching it.
    r1cs_ppzksnark_keypair<ppT> kp = r1cs_ppzksnark_generator<ppT>(cs);

    cout << "Write PK file" << endl;
    std::ofstream pk_file;
    pk_file.open(PKPATH);
    pk_file << kp.pk;
    pk_file.close();

    cout << "Write VK file" << endl;
    std::ofstream vk_file;
    vk_file.open(VKPATH);
    vk_file << kp.vk;
    vk_file.close();
cout << "Exit generator" << endl;
}

template<typename ppT>
void prover(uint32_t value)
{
    cout << "Enter prover" << endl;
    ProtoboardPtr pb = create_intkey_placeholder_protoboard();//create_intkey_set_protoboard();
    std::ifstream read_pk_file;
    read_pk_file.open(PKPATH);
    r1cs_ppzksnark_proving_key<ppT> pk;
    read_pk_file >> pk;
    read_pk_file.close();
    cout << "Exit prover" << endl;
}

template<typename ppT>
void verifier() /* todo: add proof as parameter */
{
cout << "Enter verifier" << endl;
    ProtoboardPtr pb = create_intkey_placeholder_protoboard();//create_intkey_set_protoboard();
    std::ifstream read_vk_file;
    read_vk_file.open(VKPATH);
    r1cs_ppzksnark_verification_key<ppT> vk;
    read_vk_file >> vk;
    read_vk_file.close();
cout << "Exit verifier" << endl;
}

int main () {
    cout << "Enter Main" << endl;


    generator<ppzksnark_ppT>();
    prover<ppzksnark_ppT>(4);
    verifier<ppzksnark_ppT>();
    cout << "Exit Main" << endl;
    return 0;
}
