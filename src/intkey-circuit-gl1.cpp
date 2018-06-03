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

// TODO: Using something besides the comparison gadget
protoboard<Fp> test_conjunction_gadget(const size_t n)
{
    printf("testing conjunction_gadget on all %zu bit strings\n", n);

    protoboard<Fp> pb;
    pb_variable_array<Fp> inputs;
    inputs.allocate(pb, n, "inputs");

    pb_variable<Fp> output;
    output.allocate(pb, "output");

    conjunction_gadget<Fp> c(pb, inputs, output, "c");
    c.generate_r1cs_constraints();

    for (size_t w = 0; w < 1ul<<n; ++w)
    {
        for (size_t j = 0; j < n; ++j)
        {
            pb.val(inputs[j]) = (w & (1ul<<j)) ? Fp::one() : Fp::zero();
        }

        c.generate_r1cs_witness();

        printf("positive test for %zu\n", w);
        assert(pb.val(output) == (w == (1ul<<n) - 1 ? Fp::one() : Fp::zero()));
        assert(pb.is_satisfied());

        printf("negative test for %zu\n", w);
        pb.val(output) = (w == (1ul<<n) - 1 ? Fp::zero() : Fp::one());
        assert(!pb.is_satisfied());
    }

    libff::print_time("conjunction tests successful");
    return pb;
}

protoboard<Fp> test_comparison_gadget(const size_t n)
{
    printf("testing comparison_gadget on all %zu bit inputs\n", n);

    protoboard<Fp> pb;

    pb_variable<Fp> A, B, less, less_or_eq;
    A.allocate(pb, "A");
    B.allocate(pb, "B");
    less.allocate(pb, "less");
    less_or_eq.allocate(pb, "less_or_eq");

    comparison_gadget<Fp> cmp(pb, n, A, B, less, less_or_eq, "cmp");
    cmp.generate_r1cs_constraints();

    for (size_t a = 0; a < 1ul<<n; ++a)
    {
        for (size_t b = 0; b < 1ul<<n; ++b)
        {
            pb.val(A) = Fp(a);
            pb.val(B) = Fp(b);

            cmp.generate_r1cs_witness();

#ifdef DEBUG
            printf("positive test for %zu < %zu\n", a, b);
#endif
            assert(pb.val(less) == (a < b ? Fp::one() : Fp::zero()));
            assert(pb.val(less_or_eq) == (a <= b ? Fp::one() : Fp::zero()));
            assert(pb.is_satisfied());
        }
    }

    libff::print_time("comparison tests successful");
    return pb;
}

template<typename ppT>
void generator()
{
    cout << "Enter generator" << endl;
    protoboard<Fp> pb = create_intkey_set_protoboard<Fp>();
    //protoboard<Fp> pb = test_comparison_gadget(8);
    //protoboard<Fp> pb = test_conjunction_gadget(2);

    cout << "Extract Constraint System" << endl;
    //r1cs_constraint_system<ppT> cs = pb.get_constraint_system();
    //r1cs_ppzksnark_constraint_system<ppT> cs = pb.get_constraint_system();
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
    //const size_t n = 8;
    //test_comparison_gadget(n);
    generator<ppzksnark_ppT>();
    prover<ppzksnark_ppT>(4);
    verifier<ppzksnark_ppT>();

    cout << "Exit Main" << endl;
    return 0;
}
