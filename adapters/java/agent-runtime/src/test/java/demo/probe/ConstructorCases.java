package demo.probe;

/** Real javac constructor shapes, loaded through the production focused probe composition. */
public class ConstructorCases {
  public static final RuntimeException BODY_FAILURE = new IllegalStateException("body");

  public static int compute(int seed) {
    if (seed == 0) throw new UnsupportedOperationException("argument");
    return seed;
  }

  public static int normal() {
    Chain chain = new Chain();
    return chain.value;
  }

  public static void bodyFailure() {
    new BodyThrow(true, 3L);
  }

  public static void superFailure() {
    new SuperThrow();
  }

  public static void argumentFailure() {
    new ArgumentThrow();
  }

  public static void untracedSuperFailure() {
    new UntracedSuperThrow();
  }

  public static int allocatedSuperArgument() {
    return new AllocatedArgument().value;
  }

  public static int branchedSuperArgument() {
    return new BranchedArgument(true).value;
  }

  public static int caughtBodyFailure() {
    return new BodyThrow(false, -3L).value;
  }

  public static int initialize() {
    return Initializer.value;
  }

  public static int after() {
    return 7;
  }

  /** Two hydrated owner/pet/type rows: six three-level constructor chains. */
  public static Object[] rehydrate() {
    return new Object[] {
        new EntityOwner(), new EntityPet(), new EntityType(),
        new EntityOwner(), new EntityPet(), new EntityType()
    };
  }

  public static class EntityBase {}
  public static class EntityPerson extends EntityBase {}
  public static class EntityOwner extends EntityPerson {}
  public static class EntityNamed extends EntityBase {}
  public static class EntityPet extends EntityNamed {}
  public static class EntityType extends EntityNamed {}

  public static class Base {
    public int value;

    public Base(int seed) {
      value = seed;
      if (seed < 0) throw new IllegalArgumentException("super");
      value++;
    }
  }

  public static class Chain extends Base {
    public Chain() {
      this(1);
      value += 10;
    }

    public Chain(int seed) {
      this(seed, 2L);
      value += 20;
    }

    public Chain(int seed, long increment) {
      super(compute(seed));
      value += increment;
      value += new Base(1).value;
    }
  }

  public static class BodyThrow extends Base {
    public BodyThrow(boolean fail, long increment) {
      super(compute(2));
      try {
        if (fail) throw BODY_FAILURE;
        value += increment;
        if (increment < 0) throw new IllegalArgumentException("caught");
      } catch (IllegalArgumentException caught) {
        value++;
      }
    }
  }

  public static class SuperThrow extends Base {
    public SuperThrow() {
      super(compute(-1));
      value++;
    }
  }

  public static class ArgumentThrow extends Base {
    public ArgumentThrow() {
      super(compute(0));
      value++;
    }
  }

  public static class UntracedBase {
    public UntracedBase() {
      throw new IllegalArgumentException("untraced super");
    }
  }

  public static class UntracedSuperThrow extends UntracedBase {
    public UntracedSuperThrow() {
      super();
    }
  }

  public static class AllocatedArgument extends Base {
    public AllocatedArgument() {
      super(new Base(1).value);
      value++;
    }
  }

  public static class BranchedArgument extends Base {
    public BranchedArgument(boolean first) {
      super(first ? 1 : 2);
      value++;
    }
  }

  public static class Initializer {
    public static int value;

    static {
      int first = 1;
      value = first + 1;
    }
  }
}
