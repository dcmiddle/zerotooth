#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include <stdio.h>
#include <fstream>

std::string PKPATH = "proving.key";
std::string VKPATH = "verification.key";

//Note: libsnark::default_r1cs_ppzksnark_pp is libff::default_ec_pp
typedef libsnark::default_r1cs_ppzksnark_pp ppzksnark_ppT;
typedef libff::Fr<libff::default_ec_pp> Fp;


using namespace libsnark;
using std::cout;
using std::endl;

template<typename ppT>
protoboard<Fp> create_intkey_set_protoboard(){
    cout << "Enter create protoboard" << endl;

    protoboard<Fp> pb;

    // Add "intkey set" constraint to pb (32-bit unsigned int)
    // Valid Values must be integers in the range of 0 through 232 - 1
    size_t bitLen_lt;
    pb_variable<ppT> lhs_lt, rhs_lt, less_lt, lessOrEqual_lt;

    comparison_gadget<ppT> lessThanMax(pb, bitLen_lt, lhs_lt, rhs_lt, less_lt, 
            lessOrEqual_lt, "LessThanMax");

    lessThanMax.generate_r1cs_constraints();

    size_t bitLen_gt;
    pb_variable<ppT> lhs_gt, rhs_gt, less_gt, lessOrEqual_gt;

    comparison_gadget<ppT> greaterThanMin(pb, bitLen_gt, lhs_gt, rhs_gt, 
            less_gt, lessOrEqual_gt, "greaterThanMin");

    greaterThanMin.generate_r1cs_constraints();

    return pb;
}

template<typename ppT>
void generator()
{
    cout << "Enter generator" << endl;
    protoboard<Fp> pb = create_intkey_set_protoboard<Fp>();

    cout << "Extract Constraint System" << endl;
    auto cs = pb.get_constraint_system();
    cout << "Generate Key Pair" << endl;
    // TODO: This prints a whole bunch of junk. Look into squelching it.
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
    protoboard<Fp> pb = create_intkey_set_protoboard<Fp>();
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
    protoboard<Fp> pb = create_intkey_set_protoboard<Fp>();
    std::ifstream read_vk_file;
    read_vk_file.open(VKPATH);
    r1cs_ppzksnark_verification_key<ppT> vk;
    read_vk_file >> vk;
    read_vk_file.close();
cout << "Exit verifier" << endl;
}

int main () {
    cout << "Enter Main" << endl;

    ppzksnark_ppT::init_public_params();
    generator<ppzksnark_ppT>();
    prover<ppzksnark_ppT>(4);
    verifier<ppzksnark_ppT>();

    cout << "Exit Main" << endl;
    return 0;
}
