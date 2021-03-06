"""empty message

Revision ID: caa8fc97e432
Revises: 9f7e6c2849ba
Create Date: 2020-09-07 22:14:37.320963

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'caa8fc97e432'
down_revision = '9f7e6c2849ba'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('song')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('song',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('spy_id', sa.VARCHAR(), nullable=False),
    sa.Column('upvotes', sa.INTEGER(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
