import os
import time

PROTECTED_FOLDER = "protected_folder"

DUMMY_FILE_COUNT = 30


def create_dummy_files():
    print("\n[1] Creating safe demo files...")

    for i in range(1, DUMMY_FILE_COUNT + 1):

        file_path = os.path.join(
            PROTECTED_FOLDER,
            f"document_{i}.txt"
        )

        with open(file_path, "w") as file:
            file.write(
                f"This is a harmless RansomShield demo file {i}."
            )

    print(
        f"[+] Created {DUMMY_FILE_COUNT} dummy files."
    )


def simulate_mass_modification():

    print("\n[2] Simulating rapid file modification...")

    for i in range(1, DUMMY_FILE_COUNT + 1):

        file_path = os.path.join(
            PROTECTED_FOLDER,
            f"document_{i}.txt"
        )

        with open(file_path, "a") as file:
            file.write(
                "\nSAFE SIMULATION ACTIVITY"
            )

    print("[+] Modification simulation complete.")


def simulate_mass_renaming():

    print("\n[3] Simulating mass file renaming...")

    for i in range(1, DUMMY_FILE_COUNT + 1):

        old_name = os.path.join(
            PROTECTED_FOLDER,
            f"document_{i}.txt"
        )

        new_name = os.path.join(
            PROTECTED_FOLDER,
            f"document_{i}.locked"
        )

        os.rename(old_name, new_name)

    print("[+] Renaming simulation complete.")


def main():

    print("=" * 60)
    print("        RANSHIELD SAFE ATTACK SIMULATOR")
    print("=" * 60)

    print()
    print("⚠ This is a harmless demonstration.")
    print("⚠ Only dummy files will be used.")
    print()

    input(
        "Press ENTER to start the simulation..."
    )

    create_dummy_files()

    time.sleep(1)

    simulate_mass_modification()

    time.sleep(1)

    simulate_mass_renaming()

    print()
    print("=" * 60)
    print("SAFE SIMULATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()