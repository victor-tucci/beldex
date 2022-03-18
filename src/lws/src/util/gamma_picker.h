#include <cstdint>
#include <random>
#include <vector>

namespace lws
{
    //! Select outputs using a gamma distribution with Sarang's output-lineup method
    class gamma_picker
    {
        std::vector<uint64_t> rct_offsets;
        std::gamma_distribution<double> gamma;
        double outputs_per_second;

    public:
        //! \return An upper-bound on the number of unlocked/spendable outputs based on block age.
        std::uint64_t spendable_upper_bound() const noexcept;

        //! \return True if `operator()()` can pick an output using `offsets()`.
        bool is_valid() const noexcept;
    };
}