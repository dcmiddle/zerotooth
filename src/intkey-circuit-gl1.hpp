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


template<typename Fp, typename ppT>
class IntkeyCircuit {
    private:
        //Protoboard
        protoboard<Fp> pb;

        //Protoboard variables for comparison gadgets
        //Less Than
        comparison_gadget<Fp> *lessThanMax;
        size_t bitLen_lt;
        pb_linear_combination<Fp> lhs_lt, rhs_lt;
        pb_variable<Fp> less_lt, lessOrEqual_lt;

        //Greater Than
        comparison_gadget<Fp> *greaterThanMin;
        size_t bitLen_gt;
        pb_linear_combination<Fp> lhs_gt, rhs_gt;
        pb_variable<Fp> less_gt, lessOrEqual_gt;


    public:
        IntkeyCircuit();

        //Generate the constraint system and keys
        void generate();

        //Create a proof for some intkey value
        r1cs_ppzksnark_proof<ppT> prove(uint32_t value);

        //Verify a proof of an intkey value;
        bool verify(r1cs_ppzksnark_proof<ppT> proof);

};

template<typename Fp, typename ppT>
IntkeyCircuit<Fp,ppT>::IntkeyCircuit() {
    ppT::init_public_params();

    // Add "intkey set" constraint to pb (32-bit unsigned int)
    // Valid values must be integers in the range of 0 through 2^32 - 1
    variable<Fp> A, B;
    lhs_lt.add_term(A);
    rhs_lt.add_term(B);
    lessThanMax = new comparison_gadget<Fp>(
        pb, bitLen_lt, lhs_lt, rhs_lt, less_lt, lessOrEqual_lt, "LessThanMax");

    lessThanMax->generate_r1cs_constraints();

    variable<Fp> C, D;
    lhs_gt.add_term(C);
    rhs_gt.add_term(D);
    greaterThanMin = new comparison_gadget<Fp>(
        pb, bitLen_gt, lhs_gt, rhs_gt, less_gt, lessOrEqual_gt, "greaterThanMin");

    greaterThanMin->generate_r1cs_constraints();

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
r1cs_ppzksnark_proof<ppT> IntkeyCircuit<Fp,ppT>::prove(uint32_t value)
{
    cout << "Enter prover" << endl;

    //todo: add exception handling
    std::ifstream read_pk_file;
    read_pk_file.open(PKPATH);
    r1cs_ppzksnark_proving_key<ppT> pk;
    read_pk_file >> pk;
    read_pk_file.close();

    //todo: define constants
    //Assign circuit values for lessThanMax gadget
    // value <= 2^32 - 1
    pb.val(bitLen_lt) = Fp(32);
    pb.lc_val(lhs_lt) = Fp(value);
    pb.lc_val(rhs_lt) = Fp(0xFFFFFFFF);
    pb.val(less_lt) = Fp::one();
    pb.val(lessOrEqual_lt) = Fp::one();

    //Assign circuit values for greaterThanMin gadget
    // 0 <= value
    pb.val(bitLen_gt) = Fp(32);
    pb.lc_val(lhs_gt) = Fp::zero();
    pb.lc_val(rhs_gt) = Fp(value);
    pb.val(less_gt) = Fp::one();
    pb.val(lessOrEqual_gt) = Fp::one();

    lessThanMax->generate_r1cs_witness();
    greaterThanMin->generate_r1cs_witness();

    if (!pb.is_satisfied()) {
        cout << "Error generating valid proof";
    }

    r1cs_ppzksnark_proof<ppT> proof =
        r1cs_ppzksnark_prover<ppT>(pk, pb.primary_input(), pb.auxiliary_input());

    cout << "Exit prover" << endl;
    return proof;
}

template<typename Fp, typename ppT>
bool IntkeyCircuit<Fp,ppT>::verify(r1cs_ppzksnark_proof<ppT> proof)
{
    cout << "Enter verifier" << endl;
    //todo: add exception handling
    std::ifstream read_pvk_file;
    read_pvk_file.open(PVKPATH);
    r1cs_ppzksnark_processed_verification_key<ppT> pvk;
    read_pvk_file >> pvk;
    read_pvk_file.close();

    //FIXME - write out primary input in prove();
    r1cs_primary_input<Fp> primary_input;
    r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, primary_input, proof);

    cout << "Exit verifier" << endl;
    return false;
}



#endif //_INTKEY_CIRCUIT_GL1_HPP