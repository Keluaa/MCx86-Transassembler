
#include <iostream>
#include <fstream>
#include <regex>


/**
 * Returns true if there is labels stored (as .long data) in the given section.
 * This mainly detects lookup jump tables of switches, ex:
 *      jmp [DWORD PTR .Lookup[0x0+eax]]
 *  .Lookup
 *      .long .L12
 *      .long .L52
 *      .long .L23
 *      etc...
 *
 *      .text # back to code
 *
 * This list of labels needs to have its values updated when we change the size of instructions and therefore change the
 * value of all jumps.
 */
bool check_for_labels_in_read_only_data(std::fstream& file)
{
    static const std::regex LABEL_REGEX("\\.L[0-9]+");

    std::streamoff section_start = file.tellg();

    const std::streamsize BUFFER_SIZE = 255;
    char line_buffer[BUFFER_SIZE];

    bool has_labels = false;

    while (file.good()) {
        file.getline(line_buffer, BUFFER_SIZE);
        std::string_view line(line_buffer);

        if (line.starts_with("\t.long")) {
            if (std::regex_search(line_buffer, LABEL_REGEX)) {
                has_labels = true;
                break;
            }
        }
        else if (line.starts_with("\t.text") || line.starts_with("\t.section")) {
            // End of the read-only data section
            break;
        }
    }

    file.seekg(section_start);

    return has_labels;
}


/**
 * Moves all sections of read-only data containing labels to instructions into a special section '.labels'.
 * When processing the resulting elf file, this '.labels' section will have its values changed to the new instruction
 * positions.
 *
 * Note that there is no checks made to make sure all the data in those sections contains only those labels. If they
 * don't their values will be changed regardless and create problems afterwards.
 */
void process_file(std::fstream& file)
{
    const std::streamsize BUFFER_SIZE = 255;
    char line_buffer[BUFFER_SIZE];

    int line_number = 0;

    while (file.good()) {
        file.getline(line_buffer, BUFFER_SIZE);
        std::string_view line(line_buffer);
        line_number++;

        if (line.starts_with("\t.section\t.rodata")) {
            // This part of the assembly is put in a read only section
            if (check_for_labels_in_read_only_data(file)) {
                std::cout << "Changed section of line " << line_number << "\n";
                // Change the section of this chunk of data
                file.seekg(-7, std::ios_base::cur); // Go back to the line, at 'rodata'
                file.write("labels", 6);
                file.seekg(1, std::ios_base::cur); // Next line
            }
        }
    }
}


int main(int argc, const char** argv)
{
    if (argc <= 1) {
        std::cout << "Missing input file" << std::endl;
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        const char* filename = argv[i];
        std::fstream file(filename);
        if (!file) {
            std::cerr << "Cannot open file: " << filename << std::endl;
            return 1;
        }

        std::cout << "Processing '" << filename << "'..." << std::endl;

        process_file(file);
        file.close();
    }
}
