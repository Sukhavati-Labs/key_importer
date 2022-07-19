import blspy
import click
import random


farmer_key_derive_path = (12381, 8444, 0, 0)


def derive_child_sk(sk: blspy.PrivateKey, path: tuple) -> blspy.PrivateKey:
    child_sk = sk
    for index in path:
        child_sk = blspy.AugSchemeMPL.derive_child_sk(child_sk, index)
    return child_sk


def to_bls_sk(key_string):
    try:
        return blspy.PrivateKey.from_bytes(bytes.fromhex(key_string))
    except Exception as e:
        click.echo('Wrong Key.')
        exit()


@click.command()
@click.option('--key-type', type=click.Choice(['farmer', 'master']),
              help='Chia farmer private key or master private key. Default: "farmer"',
              default='farmer')
def import_key(key_type):
    if key_type == 'master':
        chia_master_sk = click.prompt('Input Chia master private key (no echo)', hide_input=True)
        chia_master_sk = to_bls_sk(chia_master_sk)
        chia_farmer_sk = derive_child_sk(chia_master_sk, farmer_key_derive_path)
    elif key_type == 'farmer':
        chia_farmer_sk = click.prompt('Input Chia farmer private key (no echo)', hide_input=True)
        chia_farmer_sk = to_bls_sk(chia_farmer_sk)
    else:
        exit()

    chia_farmer_pk = chia_farmer_sk.get_g1()
    click.echo('Chia farmer public key: {}'.format(chia_farmer_pk))
    click.confirm('-> Confirm', default=True, abort=True)

    mask_sk = blspy.AugSchemeMPL.key_gen(bytes([random.randint(0, 255)])*32)
    agent_sk = blspy.PrivateKey.aggregate([chia_farmer_sk, mask_sk])
    click.echo('\nPlease import the following three keys into your SKT wallet:')
    click.echo('SKT mask private key: {}'.format(str(mask_sk)[12:-1]))
    click.echo('SKT agent private key: {}'.format(str(agent_sk)[12:-1]))
    click.echo('Chia farmer public key: {}'.format(chia_farmer_pk))


if __name__ == '__main__':
    import_key()
