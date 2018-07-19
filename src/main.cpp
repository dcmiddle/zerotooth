#include <iostream>
#include <intkey-circuit-gl1.hpp>

using std::cout;
using std::endl;
using namespace libsnark;

//Note: libsnark::default_r1cs_ppzksnark_pp is libff::default_ec_pp
typedef libsnark::default_r1cs_ppzksnark_pp ppzksnark_ppT;
typedef libff::Fr<libff::default_ec_pp> Fp;

int main() {
    ppzksnark_ppT::init_public_params();

    IntkeyCircuit<Fp, ppzksnark_ppT> circuit;
    circuit.generate();

    uint32_t my_secret_value = 33;
    InputAndProof input_and_proof = circuit.prove(my_secret_value);

    if(circuit.verify(input_and_proof))
        cout << "Valid Proof" << endl;
    else
        cout << "DANGER Invalid Proof" << endl;

    return 0;
}