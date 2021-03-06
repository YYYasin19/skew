"""empty message

Revision ID: 323283f34f84
Revises: caa8fc97e432
Create Date: 2020-09-07 23:35:21.595453

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '323283f34f84'
down_revision = 'caa8fc97e432'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('song',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('session_id', sa.Integer(), nullable=False),
    sa.Column('artist', sa.String(), nullable=True),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('album', sa.String(), nullable=True),
    sa.Column('cover_url', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['session_id'], ['session.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('upvote_users',
    sa.Column('song_id', sa.Integer(), nullable=False),
    sa.Column('user_token_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['song_id'], ['song.id'], ),
    sa.ForeignKeyConstraint(['user_token_id'], ['user_token.id'], ),
    sa.PrimaryKeyConstraint('song_id', 'user_token_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('upvote_users')
    op.drop_table('song')
    # ### end Alembic commands ###
