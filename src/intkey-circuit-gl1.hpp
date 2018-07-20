#ifndef _INTKEY_CIRCUIT_GL1_HPP
#define _INTKEY_CIRCUIT_GL1_HPP

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include <iostream>
#include <fstream>

std::string PKPATH = "proving.key";
std::string VKPATH = "verification.key";
std::string PVKPATH = "processed_verification.key";

using namespace libsnark;
using std::cout;
using std::endl;

// Convenience struct for packaging primary input and proof together
// TODO: cleanup templating. Consider c++11 type aliasing.
typedef struct InputAndProof {
    r1cs_primary_input<libff::Fr<libff::default_ec_pp>> input;
    r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> proof;
} InputAndProof;

template<typename Fp, typename ppT>
class IntkeyCircuit {
    private:
        //Protoboard
        protoboard<Fp> pb;

        ///Protoboard variables for comparison gadgets

        // The value we want to constrain to fall within the defined range
        pb_variable<Fp> intkey_value;

        // The min and max values to constrain intkey_value.
        pb_variable<Fp> intkey_min, intkey_max;
        
        //Boolean value we need to be true across gadgets and both less and less or eq.
        pb_variable<Fp> is_less;

        // The bit length of the value. Used to let the gadget know how to determine range.
        size_t bit_len;

        //Less Than gadget; i.e. The value is less than the intkey maximum.
        comparison_gadget<Fp> *lessThanMax;
        
        //Greater Than gadget; i.e. The value is greater than the intkey minimum.
        comparison_gadget<Fp> *greaterThanMin;


    public:
        IntkeyCircuit();

        //Generate the constraint system and keys
        void generate();

        //Create a proof for some intkey value
        InputAndProof prove(uint32_t value);

        //Verify a proof of an intkey value;
        bool verify(InputAndProof input_and_proof);
};

template<typename Fp, typename ppT>
IntkeyCircuit<Fp,ppT>::IntkeyCircuit() {
    ppT::init_public_params();

    bit_len = 32;
    intkey_value.allocate(pb, "Intkey Value");
    intkey_min.allocate(pb, "Intkey Min");
    intkey_max.allocate(pb, "Intkey Max");
    is_less.allocate(pb, "Bool for Less Than and Less or Eq");

    // Add "intkey set" constraint to pb (32-bit unsigned int)
    // Valid values must be integers in the range of 0 through 2^32 - 1
    lessThanMax = new comparison_gadget<Fp>(
        pb, bit_len, intkey_value, intkey_max, is_less, is_less, "LessThanMax");

    lessThanMax->generate_r1cs_constraints();

    greaterThanMin = new comparison_gadget<Fp>(
        pb, bit_len, intkey_min, intkey_value, is_less, is_less, "greaterThanMin");

    greaterThanMin->generate_r1cs_constraints();

    // Add constant constraints
    generate_r1cs_equals_const_constraint(pb, (pb_linear_combination<Fp>)intkey_min, Fp::zero(), \
        "Min value constant constraint of 0");
    generate_r1cs_equals_const_constraint(pb, (pb_linear_combination<Fp>)intkey_max, Fp(0xFFFFFFFF)), \
        "Max value constant constraint of 2^32-1";
    generate_r1cs_equals_const_constraint(pb, (pb_linear_combination<Fp>)is_less, Fp::one()), \
        "Constant True constraint for comparison gadgets";
}

template<typename Fp, typename ppT>
void IntkeyCircuit<Fp,ppT>::generate()
{
    // TODO: output the processed key (pvk) too.
    cout << "Enter generator" << endl;

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

    cout << "Write Processed_VK file" << endl;
    std::ofstream pvk_file;
    pvk_file.open(PVKPATH);
    auto pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(kp.vk);
    pvk_file << pvk;
    pvk_file.close();
    cout << "Exit generator" << endl;
}

template<typename Fp, typename ppT>
InputAndProof IntkeyCircuit<Fp,ppT>::prove(uint32_t value)
{
    cout << "Enter prover" << endl;

    //todo: add exception handling
    std::ifstream read_pk_file;
    read_pk_file.open(PKPATH);
    r1cs_ppzksnark_proving_key<ppT> pk;
    read_pk_file >> pk;
    read_pk_file.close();

    //todo: define constants
    //Assign circuit variables to prove: min <= value <= max
    pb.val(bit_len) = Fp(32);
    pb.val(intkey_value) = Fp(value);
    pb.val(intkey_min) = Fp::zero();
    pb.val(intkey_max) = Fp(0xFFFFFFFF);
    pb.val(is_less) = Fp::one();

    lessThanMax->generate_r1cs_witness();
    greaterThanMin->generate_r1cs_witness();

    if (!pb.is_satisfied()) {
        cout << "Error generating valid proof" << endl;
    } else {
        cout << "Constraints satisfied" << endl;
    }

    r1cs_ppzksnark_proof<ppT> proof =
        r1cs_ppzksnark_prover<ppT>(pk, pb.primary_input(), pb.auxiliary_input());

    InputAndProof input_and_proof;
    input_and_proof.input = pb.primary_input();
    input_and_proof.proof = proof;
    cout << "Exit prover" << endl;
    return input_and_proof;
}

template<typename Fp, typename ppT>
bool IntkeyCircuit<Fp,ppT>::verify(InputAndProof input_and_proof)
{
    cout << "Enter verifier" << endl;
    //todo: add exception handling
    std::ifstream read_pvk_file;
    read_pvk_file.open(PVKPATH);
    r1cs_ppzksnark_processed_verification_key<ppT> pvk;
    read_pvk_file >> pvk;
    read_pvk_file.close();

    bool result;
    result = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, input_and_proof.input, input_and_proof.proof);

    cout << "Exit verifier" << endl;
    return result;
}



#endif //_INTKEY_CIRCUIT_GL1_HPP